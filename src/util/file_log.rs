// Copyright 2016 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fs::{self, metadata, read_dir, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const FLUSHES_BEFORE_ESTIMATE_RENEWAL: u8 = 10;

fn open_log_file<P>(path: P) -> io::Result<File>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    let parent = path.parent().unwrap();
    if !parent.is_dir() {
        fs::create_dir_all(parent)?
    }
    OpenOptions::new().append(true).create(true).open(path)
}

pub struct RotatingFileLogger {
    file_path: PathBuf,
    file: File,
    /// The max size of the file, in bytes.
    rollover_size: u64,

    /// A rough estimate of the current size of the file.
    ///
    /// Checking the size of the file from the metadata takes approximately 800ns on a modern Linux
    /// machine with an EXT4 filesystem. This is too slow to check every log record written.
    ///
    /// Since it is an estimate it may drift (significantly) if there is mutation of the actual
    /// file on disk.
    estimated_file_size: u64,
    /// The number of `flush()` calls since last `estimated_current_size` is updated.
    flushes_since_last_estimate: u8,
}

impl RotatingFileLogger {
    pub fn new<P>(path: P, rollover_size: u64) -> io::Result<RotatingFileLogger>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let file = open_log_file(path)?;
        let estimated_file_size = metadata(path)?.len();
        let ret = RotatingFileLogger {
            rollover_size,
            estimated_file_size,
            flushes_since_last_estimate: 0,
            file_path: path.to_owned(),
            file,
        };
        Ok(ret)
    }

    fn open(&mut self) -> io::Result<()> {
        self.file = open_log_file(&self.file_path)?;
        self.estimated_file_size = metadata(&self.file_path)
            .map(|metadata| metadata.len())?;
        self.flushes_since_last_estimate = 0;
        Ok(())
    }

    fn should_rollover(&mut self) -> io::Result<bool> {
        if self.flushes_since_last_estimate >= FLUSHES_BEFORE_ESTIMATE_RENEWAL {
            self.estimated_file_size = metadata(self.file_path.clone())
                .map(|metadata| metadata.len())?;
            self.flushes_since_last_estimate = 0;
        }
        Ok(self.estimated_file_size >= self.rollover_size)
    }

    fn do_rollover(&mut self) -> io::Result<()> {
        self.close()?;
        let mut next = self.file_path.clone();
        next.set_file_name(self.next_rollover_log_filename());
        fs::rename(&self.file_path, &next)?;
        self.open()
    }

    fn close(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    fn next_rollover_log_filename(&self) -> PathBuf {
        let parent = self.file_path.parent().unwrap();
        let log_file_name = self.file_path.file_name().and_then(|f| f.to_str()).unwrap();
        let entries = read_dir(parent)
            .expect("parent folder of log file was not a directory.")
            .filter_map(|maybe_entry| {
                let entry = maybe_entry.ok()?;
                let file_name = entry.file_name();
                let file_name = file_name.to_str()?;
                if file_name.starts_with(log_file_name) {
                    let number: usize = file_name.split('.').last()?.parse().ok()?;
                    Some(number)
                } else {
                    None
                }
            });
        let next = entries.max().unwrap_or(0) + 1;
        format!(
            "{log_file_name}.{next:06}",
            log_file_name = log_file_name,
            next = next
        ).into()
    }
}

impl Write for RotatingFileLogger {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.file.write(bytes)?;
        self.estimated_file_size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes_since_last_estimate += 1;
        self.file.flush()?;
        if self.should_rollover()? {
            self.do_rollover()?;
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{read_dir, OpenOptions};
    use std::io::prelude::*;

    use super::{RotatingFileLogger, FLUSHES_BEFORE_ESTIMATE_RENEWAL};
    use tempdir::TempDir;

    #[test]
    fn test_next_rollover_log_filename() {
        let tmp_dir = TempDir::new("").unwrap();
        let log_file = tmp_dir
            .path()
            .join("test_next_rollover_log_filename.log")
            .to_str()
            .unwrap()
            .to_string();
        let mut logger = RotatingFileLogger::new(&log_file, 1).unwrap();
        for index in 1..100 {
            let next = logger.next_rollover_log_filename();
            let expected = format!("test_next_rollover_log_filename.log.{:06}", index);
            assert_eq!(next.to_str().unwrap(), expected);
            // Force a rollover.
            logger.write_all(&[0_u8; 16]).unwrap();
            logger.flush().unwrap();
        }
    }

    #[test]
    fn test_rotating_file_logger_rollover() {
        const ROTATION_SIZE: u64 = 16;
        let tmp_dir = TempDir::new("").unwrap();
        let log_file = tmp_dir
            .path()
            .join("test_rotating_file_logger_rollover.log")
            .to_str()
            .unwrap()
            .to_string();
        let mut logger = RotatingFileLogger::new(&log_file, ROTATION_SIZE).unwrap();
        for index in 1..100 {
            // Not enough to roll over.
            logger.write_all(&[0_u8; (ROTATION_SIZE - 1) as usize]).unwrap();
            logger.flush().unwrap();
            assert_eq!(read_dir(tmp_dir.path()).unwrap().count(), index);
            // Enough to roll over.
            logger.write_all(&[0_u8; 1]).unwrap();
            logger.flush().unwrap();
            assert_eq!(read_dir(tmp_dir.path()).unwrap().count(), index + 1);
        }
    }

    #[test]
    fn test_rotating_file_logger_estimate() {
        const ROTATION_SIZE: u64 = 10;
        let tmp_dir = TempDir::new("").unwrap();
        let log_file = tmp_dir
            .path()
            .join("test_rotating_file_logger_estimate_renewal.log")
            .to_str()
            .unwrap()
            .to_string();
        let mut logger = RotatingFileLogger::new(&log_file, ROTATION_SIZE).unwrap();
        // Ensure the estimate is being incremented.
        logger.write_all(&[0_u8; 1]).unwrap();
        assert_eq!(logger.estimated_file_size, 1);
        logger.write_all(&[0_u8; 1]).unwrap();
        assert_eq!(logger.estimated_file_size, 2);

        // Ensure the flushes are being tracked.
        assert_eq!(logger.flushes_since_last_estimate, 0);
        logger.flush().unwrap();
        assert_eq!(logger.flushes_since_last_estimate, 1);

        // Open again and write to the file as well, this should make the esimate incorrect.
        let mut other_handle = OpenOptions::new().append(true).create(true).open(log_file).unwrap();
        other_handle.write_all(&[0_u8; 1]).unwrap();
        other_handle.flush().unwrap();
        // Since we're writing from the other handle the estimate isn't updated.
        assert_eq!(logger.estimated_file_size, 2);
        assert_eq!(read_dir(tmp_dir.path()).unwrap().count(), 1);

        // We've already flushed the logger once, now flush it until it is almost ready to renew
        // its estimate.
        while logger.flushes_since_last_estimate < (FLUSHES_BEFORE_ESTIMATE_RENEWAL -1) {
            logger.flush().unwrap()
        }

        // Ensure it still hasn't refreshed its estimate.
        assert_eq!(logger.estimated_file_size, 2);
        assert_eq!(logger.flushes_since_last_estimate, FLUSHES_BEFORE_ESTIMATE_RENEWAL -1);

        // At this point the flush will renew the estimate.
        logger.flush().unwrap();
        assert_eq!(logger.flushes_since_last_estimate, 0);
        assert_eq!(logger.estimated_file_size, 3);

        // Write enough to force a rollover, creating a new file.
        logger.write_all(&[0_u8; 7]).unwrap();
        logger.flush().unwrap();
        assert_eq!(read_dir(tmp_dir.path()).unwrap().count(), 2);
        assert_eq!(logger.flushes_since_last_estimate, 0);
        assert_eq!(logger.estimated_file_size, 0);
    }
}
