use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::path::Path;

pub struct PcapFileReader {
    reader: PcapReader<File>,
}

impl PcapFileReader {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, ReaderError> {
        let file = File::open(path).map_err(ReaderError::Io)?;
        let reader = PcapReader::new(file).map_err(ReaderError::Pcap)?;
        Ok(Self { reader })
    }
    
    pub fn next_packet(&mut self) -> Option<Result<(f64, Vec<u8>), ReaderError>> {
        match self.reader.next_packet() {
            Some(Ok(pkt)) => {
                let ts = pkt.timestamp.as_secs_f64();
                Some(Ok((ts, pkt.data.into_owned())))
            },
            Some(Err(e)) => Some(Err(ReaderError::Pcap(e))),
            None => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReaderError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PCAP error: {0}")]
    Pcap(#[from] pcap_file::PcapError),
}
