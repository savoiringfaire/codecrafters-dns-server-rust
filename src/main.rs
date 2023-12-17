use std::net::UdpSocket;
use anyhow::Context;
use anyhow::anyhow;

struct Packet {
    /// The header section is always present.  The header includes fields that
    /// specify which of the remaining sections are present, and also specify
    /// whether the message is a query or a response, a standard query or some
    /// other opcode, etc.
    header: Header
}

impl Packet {
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(Self{
            header: Header::from_bytes(&bytes[0..12]).context("decoding header")?
        })
    }

    pub fn encode(self) -> Vec<u8> {
        self.header.encode().to_vec()
    }
}

struct Header {
    /// A 16 bit identifier assigned by the 'querier'. To be copied to replies to match up.
    id: u16,

    /// A one bit field that specifies whether this message is a query (0), or a response (1).
    packet_type: PacketType,

    /// A four bit field that specifies kind of query in this
    /// message.  This value is set by the originator of a query
    /// and copied into the response.
    opcode: OperationCode,

    /// this bit is valid in responses,
    /// and specifies that the responding name server is an
    /// authority for the domain name in question section.
    /// Note that the contents of the answer section may have
    /// multiple owner names because of aliases.  The AA bit
    /// corresponds to the name which matches the query name, or
    /// the first owner name in the answer section.
    authoratitive_answer: bool,

    /// TrunCation - specifies that this message was truncated
    /// due to length greater than that permitted on the
    /// transmission channel.
    truncation: bool,

    /// this bit may be set in a query and
    /// is copied into the response.  If RD is set, it directs
    /// the name server to pursue the query recursively.
    /// Recursive query support is optional.
    recursion_desired: bool,

    /// this be is set or cleared in a
    /// response, and denotes whether recursive query support is
    /// available in the name server.
    recursion_available: bool,

    /// Reserved for future use, must always be zero.
    z: Z,

    /// Response code - this 4 bit field is set as part of responses.
    response_code: ResponseCode,

    /// The number of entries in the question section.
    question_count: u16,

    /// The number of entries in the answer section.
    answer_count: u16,

    /// The number of name server resource records in the authority records section.
    name_server_count: u16,

    /// The number of resource records in the additional records section
    additional_records_count: u16
}

impl Header {
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 12 {
            return Err(anyhow!("Incorrect header byte length given: {}", bytes.len()))
        }

        Ok(Self {
            // TODO: Proper handling of endianess here
            id: (bytes[0] as u16) << 8 | bytes[1] as u16,
            packet_type: PacketType::try_from(bytes[2] & 0x80).context("Packet type to be valid")?,
            opcode: OperationCode::try_from((bytes[2] & 0x78) >> 3).context("Opcode type to be valid")?,
            authoratitive_answer: bytes[2] & 0x04 != 0,
            truncation: bytes[2] & 0x02 != 0,
            recursion_desired: bytes[2] & 0x01 != 0,
            recursion_available: bytes[3] & 0x80 != 0,
            z: Z::Always,
            response_code: ResponseCode::try_from(bytes[3] & 0x0F).context("Response code type to be valid")?,
            question_count: (bytes[4] as u16) << 8 | bytes[5] as u16,
            answer_count: (bytes[6] as u16) << 8 | bytes[7] as u16,
            name_server_count: (bytes[8] as u16) << 8 | bytes[9] as u16,
            additional_records_count: (bytes[10] as u16) << 8 | bytes[11] as u16,
        })
    }

    pub fn encode(self) -> [u8; 12] {
        [
            // TODO: More efficient way than calling to_be_bytes twice?
            self.id.to_be_bytes()[0],
            self.id.to_be_bytes()[1],
            (self.packet_type as u8) << 7 | (self.opcode as u8) << 3 | (self.authoratitive_answer as u8) << 2 | (self.truncation as u8) << 1 | (self.recursion_desired as u8),
            (self.recursion_available as u8) << 7 | 0 << 4 | (self.response_code as u8),
            self.question_count.to_be_bytes()[0],
            self.question_count.to_be_bytes()[1],
            self.answer_count.to_be_bytes()[0],
            self.answer_count.to_be_bytes()[1],
            self.name_server_count.to_be_bytes()[0],
            self.name_server_count.to_be_bytes()[1],
            self.additional_records_count.to_be_bytes()[0],
            self.additional_records_count.to_be_bytes()[1]
        ]
    }
}

enum ResponseCode {
    /// No error condition
    Success = 0,

    /// Format error - The name server was unable to interpret the query.
    FormatError = 1,

    /// Server failure - The name server was unable to process this query due to a problem with the name server.
    ServerFailure = 2,

    /// Name Error - Meaningful only for
    /// responses from an authoritative name
    /// server, this code signifies that the
    /// domain name referenced in the query does
    /// not exist.
    NameError = 3,

    /// Not Implemented - The name server does not support the requested kind of query
    NotImplemented = 4,

    /// Refused - The name server refuses to perform the operation for policy reasons.
    ///
    /// For example, a name
    /// server may not wish to provide the
    /// information to the particular requester,
    /// or a name server may not wish to perform
    /// a particular operation (e.g., zone transfer) for particular data.
    Refused = 5
}

impl TryFrom<u8> for ResponseCode {
    type Error = anyhow::Error;

    fn try_from(from: u8) -> anyhow::Result<Self> {
        match from {
            0 => Ok(ResponseCode::Success),
            1 => Ok(ResponseCode::FormatError),
            2 => Ok(ResponseCode::ServerFailure),
            3 => Ok(ResponseCode::NameError),
            4 => Ok(ResponseCode::NotImplemented),
            5 => Ok(ResponseCode::Refused),
            _ => Err(anyhow!("Invalid response code"))
        }
    }
}

enum Z {
    Always = 0
}

enum PacketType {
    Query = 0,
    Response = 1
}

impl TryFrom<u8> for PacketType {
    type Error = anyhow::Error;

    fn try_from(from: u8) -> anyhow::Result<Self> {
        match from {
            0 => Ok(PacketType::Query),
            1 => Ok(PacketType::Response),
            _ => Err(anyhow!("Invalid packet type received"))
        }
    }
}

enum OperationCode {
    /// a standard query (QUERY)
    Query = 0,
    /// an inverse query (IQUERY)
    IQuery = 1,
    /// a server status request (STATUS)
    Status = 2
}

impl TryFrom<u8> for OperationCode {
    type Error = anyhow::Error;

    fn try_from(from: u8) -> anyhow::Result<Self> {
        match from {
            0 => Ok(OperationCode::Query),
            1 => Ok(OperationCode::IQuery),
            2 => Ok(OperationCode::Status),
            _ => Err(anyhow!("Invalid operation code received"))
        }
    }
}

fn main() -> anyhow::Result<()> {
    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let _received_data = String::from_utf8_lossy(&buf[0..size]);

                let req = Packet::from_bytes(&buf)?;

                println!("Received {} bytes from {}", size, source);
                let response = Packet{
                    header: Header {
                        id: req.header.id,
                        packet_type: PacketType::Response,
                        opcode: OperationCode::Query,
                        authoratitive_answer: false,
                        truncation: false,
                        recursion_desired: false,
                        recursion_available: false,
                        z: Z::Always,
                        response_code: ResponseCode::Success,
                        question_count: 0,
                        answer_count: 0,
                        name_server_count: 0,
                        additional_records_count: 0,
                    }
                }.encode();

                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }

    Ok(())
}
