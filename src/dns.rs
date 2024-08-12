use std::net::{IpAddr, UdpSocket};
use tokio::net::UdpSocket as TokioUdpSocket;

const DNS_SERVER: &str = "8.8.8.8:53";

#[derive(Debug, Clone, Copy)]
struct DnsHeader {
  transaction_id: u16,
  flags: u16,
  questions: u16,
  answers: u16,
  authority: u16,
  additional: u16,
}

impl DnsHeader {
  fn new() -> Self {
    Self {
      transaction_id: 0x1234, // トランザクションIDは通常ランダムに生成する
      flags: 0x0100, // 標準クエリ
      questions: 1,
      answers: 0,
      authority: 0,
      additional: 0,
    }
  }

  fn to_bytes(&self) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&self.transaction_id.to_be_bytes());
    bytes.extend_from_slice(&self.flags.to_be_bytes());
    bytes.extend_from_slice(&self.questions.to_be_bytes());
    bytes.extend_from_slice(&self.answers.to_be_bytes());
    bytes.extend_from_slice(&self.authority.to_be_bytes());
    bytes.extend_from_slice(&self.additional.to_be_bytes());
    bytes
  }
}

#[derive(Debug, Clone)]
struct DnsQuestion {
    name: String,
    qtype: u16,
    qclass: u16,
}

impl DnsQuestion {
    fn new(name: String) -> Self {
        Self {
            name,
            qtype: 1, // A レコード
            qclass: 1, // IN
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for part in self.name.split('.') {
            bytes.push(part.len() as u8);
            bytes.extend_from_slice(part.as_bytes());
        }
        bytes.push(0); // 終端
        bytes.extend_from_slice(&self.qtype.to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());
        bytes
    }
}

struct DnsQuery {
  header: DnsHeader,
  question: DnsQuestion,
}

impl DnsQuery {
  fn new(name: String) -> Self {
      Self {
          header: DnsHeader::new(),
          question: DnsQuestion::new(name),
      }
  }

  fn to_bytes(&self) -> Vec<u8> {
      let mut bytes = self.header.to_bytes();
      bytes.extend(self.question.to_bytes());
      bytes
  }
}

pub fn build_dns_query(name: &str) -> Vec<u8> {
  DnsQuery::new(name.to_string()).to_bytes()
}

pub async fn resolve_dns_query(name: &str) -> Result<Vec<IpAddr>, String> {
  let query = DnsQuery::new(name.to_string()).to_bytes();
  let socket = TokioUdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
  socket.connect(DNS_SERVER).await.map_err(|e| e.to_string())?;

  socket.send(&query).await.map_err(|e| e.to_string())?;
  let mut response = [0u8; 512];
  let _received = socket.recv(&mut response).await.map_err(|e| e.to_string())?;

  parse_dns_response(&response)
}

pub fn parse_dns_response(response: &[u8]) -> Result<Vec<IpAddr>, String> {
  if response.len() < 12 {
      return Err("Response too short".to_string());
  }

  let mut ip_addresses = Vec::new();

  let transaction_id = u16::from_be_bytes([response[0], response[1]]);
  let flags = u16::from_be_bytes([response[2], response[3]]);
  let questions = u16::from_be_bytes([response[4], response[5]]);
  let answer_rrs = u16::from_be_bytes([response[6], response[7]]);
  let authority_rrs = u16::from_be_bytes([response[8], response[9]]);
  let additional_rrs = u16::from_be_bytes([response[10], response[11]]);

  // DNS応答パケットの質問セクションをスキップ
  let mut pos = 12;
  for _ in 0..questions {
      while pos < response.len() && response[pos] != 0 {
          pos += 1 + response[pos] as usize;
      }
      pos += 5; // 終端の0とタイプ、クラスの2バイトずつ
  }

  // 応答セクションを解析
  for _ in 0..answer_rrs {
      if pos + 12 > response.len() {
          return Err("Invalid response format".to_string());
      }

      pos += 2; // 名前（ポインター）

      let typ = u16::from_be_bytes([response[pos], response[pos + 1]]);
      pos += 8; // タイプ、クラス、TTLをスキップ

      let data_len = u16::from_be_bytes([response[pos], response[pos + 1]]);
      pos += 2;

      if typ == 1 && data_len == 4 { // A レコードでIPv4アドレス
          if pos + 4 > response.len() {
              return Err("Invalid response format".to_string());
          }

          let ip = IpAddr::from([response[pos], response[pos + 1], response[pos + 2], response[pos + 3]]);
          ip_addresses.push(ip);
          pos += 4;
      } else {
          pos += data_len as usize;
      }
  }

  Ok(ip_addresses)
}