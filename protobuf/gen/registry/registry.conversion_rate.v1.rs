/// Instruct the NNS about the market value of 1 ICP as measured by
/// an IMF SDR.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct IcpXdrConversionRateRecord {
    /// The time for which the market data was queried, expressed in Unix
    /// time seconds.
    #[prost(uint64, tag="1")]
    pub timestamp_seconds: u64,
    /// The number of 100ths of IMF SDR (currency code XDR) that corresponds to 1
    /// ICP. Reflects the current market price of one ICP token. In other words,
    /// this value specifies the ICP/XDR conversion rate to two decimal places.
    #[prost(uint64, tag="2")]
    pub xdr_per_icp: u64,
}
