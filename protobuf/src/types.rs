pub mod v1 {
    use prost::Message;
    use std::fs::File;
    use std::io::Read;
    use std::io::Write;
    use std::path::Path;

    include!(std::concat!("../gen/types/types.v1.rs"));

    impl CatchUpPackage {
        /// Read and deserialize a protobuf CatchUpPackage from the provided
        /// file.
        pub fn read_from_file<P: AsRef<Path> + std::fmt::Debug>(
            filepath: P,
        ) -> Result<Self, String> {
            let mut cup_file = File::open(&filepath)
                .map_err(|e| format!("Failed to open protobuf file at {:?} {:?}", filepath, e))?;
            let mut buf = Vec::new();
            cup_file
                .read_to_end(&mut buf)
                .map_err(|e| format!("Failed to read file {:?} {:?}", filepath, e))?;
            Self::decode(&buf[..])
                .map_err(|e| format!("Failed decode protobuf at {:?} {:?}", filepath, e))
        }

        /// Write the protobuf to the provided file.
        pub fn write_to_file<P: AsRef<Path> + std::fmt::Debug>(
            &self,
            filepath: P,
        ) -> Result<(), std::io::Error> {
            let mut buf = Vec::<u8>::new();
            self.encode(&mut buf).expect("CUP should serialize");
            let mut cup_file = File::create(&filepath)?;
            cup_file.write(&buf).map(|_| ())
        }
    }

    impl CatchUpContent {
        pub fn as_protobuf_vec(&self) -> Vec<u8> {
            let mut buf = Vec::<u8>::new();
            self.encode(&mut buf)
                .expect("CatchUpContent should serialize");
            buf
        }
    }
}
