use anyhow::anyhow;
use anyhow::Context;
use byteorder::{ByteOrder, NetworkEndian};

#[derive(Debug, Clone)]
pub struct Packet {
    /// The header section is always present.  The header includes fields that
    /// specify which of the remaining sections are present, and also specify
    /// whether the message is a query or a response, a standard query or some
    /// other opcode, etc.
    pub header: Header,

    pub questions: Vec<Question>,

    pub answers: Vec<Answer>,
}

impl TryFrom<&[u8]> for Packet {
    type Error = anyhow::Error;

    fn try_from(from: &[u8]) -> anyhow::Result<Packet> {
        let header = Header::from_bytes(&from[0..12]).context("decoding header")?;
        let mut questions = Vec::with_capacity(header.question_count as usize);
        let mut answers = Vec::with_capacity(header.answer_count as usize);

        let mut remaining = &from.as_ref()[12..];

        for _ in 0..header.question_count {
            let question: Question;
            (remaining, question) = Question::from_bytes(&remaining, &from)?;

            questions.push(question)
        }

        for _ in 0..header.answer_count {
            let answer: Answer;
            (remaining, answer) = Answer::from_bytes(&remaining, &from)?;

            answers.push(answer);
        }

        Ok(Self {
            header,
            questions,
            answers,
        })
    }
}

impl<'a> Packet {
    #[inline]
    pub fn new(id: u16, packet_type: PacketType, response_code: ResponseCode) -> Self {
        Self {
            header: Header {
                id,
                packet_type,
                response_code,
                opcode: OperationCode::Query,
                truncation: false,
                authoratitive_answer: false,
                recursion_desired: false,
                recursion_available: false,
                z: Z::Always,
                question_count: 0,
                answer_count: 0,
                name_server_count: 0,
                additional_records_count: 0,
            },
            questions: vec![],
            answers: vec![],
        }
    }

    #[inline]
    pub fn with_answers(mut self, answers: &mut Vec<Answer>) -> Self {
        self.header.answer_count += answers.len() as u16;
        self.answers.append(answers);
        self
    }

    #[inline]
    pub fn with_answer(mut self, answer: Answer) -> Self {
        self.answers.push(answer);
        self.header.answer_count += 1;
        self
    }

    #[inline]
    pub fn with_questions(mut self, questions: &mut Vec<Question>) -> Self {
        self.header.question_count += questions.len() as u16;
        self.questions.append(questions);
        self
    }

    #[inline]
    pub fn with_question(mut self, question: Question) -> Self {
        self.questions.push(question);
        self.header.question_count += 1;
        self
    }

    #[inline]
    pub fn with_opcode(mut self, opcode: OperationCode) -> Self {
        self.header.opcode = opcode;
        self
    }

    #[inline]
    pub fn with_recursion_desired(mut self, desired: bool) -> Self {
        self.header.recursion_desired = desired;
        self
    }

    #[inline]
    pub fn recursion_desired(&self) -> bool {
        self.header.recursion_desired
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let header = self.header.encode().to_vec();

        let mut questions: Vec<u8> = Vec::with_capacity(self.header.question_count as usize);
        for question in self.questions.clone() {
            questions.append(&mut question.encode()?);
        }

        let mut answers: Vec<u8> = Vec::with_capacity(self.header.answer_count as usize);
        for answer in self.answers.clone() {
            answers.append(&mut answer.encode()?);
        }

        Ok([header, questions, answers].concat())
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    /// A 16 bit identifier assigned by the 'querier'. To be copied to replies to match up.
    pub id: u16,

    /// A one bit field that specifies whether this message is a query (0), or a response (1).
    pub packet_type: PacketType,

    /// A four bit field that specifies kind of query in this
    /// message.  This value is set by the originator of a query
    /// and copied into the response.
    pub opcode: OperationCode,

    /// this bit is valid in responses,
    /// and specifies that the responding name server is an
    /// authority for the domain name in question section.
    /// Note that the contents of the answer section may have
    /// multiple owner names because of aliases.  The AA bit
    /// corresponds to the name which matches the query name, or
    /// the first owner name in the answer section.
    pub authoratitive_answer: bool,

    /// TrunCation - specifies that this message was truncated
    /// due to length greater than that permitted on the
    /// transmission channel.
    pub truncation: bool,

    /// this bit may be set in a query and
    /// is copied into the response.  If RD is set, it directs
    /// the name server to pursue the query recursively.
    /// Recursive query support is optional.
    pub recursion_desired: bool,

    /// this be is set or cleared in a
    /// response, and denotes whether recursive query support is
    /// available in the name server.
    pub recursion_available: bool,

    /// Reserved for future use, must always be zero.
    #[allow(unused)]
    pub z: Z,

    /// Response code - this 4 bit field is set as part of responses.
    pub response_code: ResponseCode,

    /// The number of entries in the question section.
    pub question_count: u16,

    /// The number of entries in the answer section.
    pub answer_count: u16,

    /// The number of name server resource records in the authority records section.
    pub name_server_count: u16,

    /// The number of resource records in the additional records section
    pub additional_records_count: u16,
}

impl Header {
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 12 {
            return Err(anyhow!(
                "Incorrect header byte length given: {}",
                bytes.len()
            ));
        }

        Ok(Self {
            id: NetworkEndian::read_u16(&[bytes[0], bytes[1]]),
            packet_type: PacketType::try_from((bytes[2] & 0x80) >> 7)
                .context("Packet type to be valid")?,
            opcode: OperationCode::try_from((bytes[2] & 0x78) >> 3)
                .context("Opcode type to be valid")?,
            authoratitive_answer: bytes[2] & 0x04 != 0,
            truncation: bytes[2] & 0x02 != 0,
            recursion_desired: bytes[2] & 0x01 != 0,
            recursion_available: bytes[3] & 0x80 != 0,
            z: Z::Always,
            response_code: ResponseCode::try_from(bytes[3] & 0x0F)
                .context("Response code type to be valid")?,
            question_count: NetworkEndian::read_u16(&[bytes[4], bytes[5]]),
            answer_count: NetworkEndian::read_u16(&[bytes[6], bytes[7]]),
            name_server_count: NetworkEndian::read_u16(&[bytes[8], bytes[9]]),
            additional_records_count: NetworkEndian::read_u16(&[bytes[10], bytes[11]]),
        })
    }

    pub fn encode(&self) -> [u8; 12] {
        [
            // TODO: More efficient way than calling to_be_bytes twice?
            self.id.to_be_bytes()[0],
            self.id.to_be_bytes()[1],
            (self.packet_type as u8) << 7
                | (u8::from(self.opcode)) << 3
                | (self.authoratitive_answer as u8) << 2
                | (self.truncation as u8) << 1
                | (self.recursion_desired as u8),
            (self.recursion_available as u8) << 7 | 0 << 4 | (self.response_code as u8),
            self.question_count.to_be_bytes()[0],
            self.question_count.to_be_bytes()[1],
            self.answer_count.to_be_bytes()[0],
            self.answer_count.to_be_bytes()[1],
            self.name_server_count.to_be_bytes()[0],
            self.name_server_count.to_be_bytes()[1],
            self.additional_records_count.to_be_bytes()[0],
            self.additional_records_count.to_be_bytes()[1],
        ]
    }
}

#[derive(Debug, Clone)]
pub struct Labels(Vec<String>);

impl<'a> Labels {
    pub fn from_bytes(bytes: &'a [u8], full_message: &'a [u8]) -> anyhow::Result<(&'a [u8], Self)> {
        let mut labels: Vec<String> = Vec::new();

        let mut offset = 0;

        // TODO: This is not bounds-checked properly.
        //       Shouldn't fail on correct input. All bets are off on incorrect input.
        while bytes[offset] != 0 {
            let label_len = bytes[offset] as usize;
            if label_len & 0xC0 == 0xC0 {
                // This is a pointer
                let pointer: usize =
                    NetworkEndian::read_u16(&[bytes[offset] & 0x3f, bytes[offset + 1]]) as usize;

                let (_, mut pointer_labels) =
                    Self::from_bytes(&full_message[pointer..], &full_message)
                        .context("parsing pointer")?;
                labels.append(&mut pointer_labels.0);
                offset += 1;

                // A label must only *end* with a pointer.
                break;
            } else {
                labels.push(
                    // TODO: Proper error handling here.
                    String::from_utf8(bytes[offset + 1..offset + 1 + label_len].to_vec())
                        .context("Creating str from label")?,
                );
                offset += label_len + 1;
            }
        }

        Ok((&bytes[offset + 1..], Self(labels)))
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let mut labels: Vec<u8> = Vec::new();

        for label in &self.0 {
            if label.len() > u8::MAX as usize {
                return Err(anyhow!(
                    "Name part `{}` longer than max `{}`",
                    label,
                    u8::MAX
                ));
            }

            labels.append(&mut [&[label.len() as u8], label.as_bytes()].concat().to_vec())
        }

        labels.push(0x00);

        Ok(labels)
    }
}

#[derive(Debug, Clone)]
pub struct Question {
    /// A domain name, represented as a sequence of "labels"
    /// each label represents a part of the domain (e.g. 'google', 'com')
    pub name: Labels,

    /// the type of record
    pub record_type: RecordType,

    /// Rarely used, not implemented.
    pub class: u16,
}

impl<'a> Question {
    pub fn from_bytes(bytes: &'a [u8], full_message: &'a [u8]) -> anyhow::Result<(&'a [u8], Self)> {
        let (remaining, name) =
            Labels::from_bytes(&bytes, full_message).context("Decoding question labels")?;

        Ok((
            &remaining[4..],
            Question {
                name,
                record_type: NetworkEndian::read_u16(&[remaining[0], remaining[1]]).try_into()?,
                class: NetworkEndian::read_u16(&[remaining[2], remaining[3]]),
            },
        ))
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok([
            self.name.encode()?,
            (self.record_type as u16).to_be_bytes().to_vec(),
            self.class.to_be_bytes().to_vec(),
        ]
        .concat()
        .to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct Answer {
    /// a domain name to which this resource record pertains.
    pub name: Labels,

    /// two octets containing one of the RR type codes.  This
    /// field specifies the meaning of the data in the RDATA
    /// field.
    pub answer_type: RecordType,

    /// two octets which specify the class of the data in the RDATA field.
    pub class: u16,

    /// a 32 bit unsigned integer that specifies the time
    /// interval (in seconds) that the resource record may be
    /// cached before it should be discarded.  Zero values are
    /// interpreted to mean that the RR can only be used for the
    /// transaction in progress, and should not be cached.
    pub ttl: u32,

    /// an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    pub rdlength: u16,

    /// a variable length string of octets that describes the
    /// resource.  The format of this information varies
    /// according to the TYPE and CLASS of the resource record.
    /// For example, the if the TYPE is A and the CLASS is IN,
    /// the RDATA field is a 4 octet ARPA Internet address.
    pub rdata: ResponseData,
}

impl<'a> Answer {
    pub fn from_bytes(bytes: &'a [u8], full_message: &'a [u8]) -> anyhow::Result<(&'a [u8], Self)> {
        let (remaining, name) =
            Labels::from_bytes(&bytes, full_message).context("Decoding question labels")?;

        Ok((
            &remaining[4..],
            Answer {
                name,
                answer_type: NetworkEndian::read_u16(&[remaining[0], remaining[1]]).try_into()?,
                class: NetworkEndian::read_u16(&[remaining[2], remaining[3]]),
                ttl: NetworkEndian::read_u32(&[
                    remaining[4],
                    remaining[5],
                    remaining[6],
                    remaining[7],
                ]),
                rdlength: NetworkEndian::read_u16(&[remaining[8], remaining[9]]),
                rdata: ResponseData::Ipv4([
                    remaining[10],
                    remaining[11],
                    remaining[12],
                    remaining[13],
                ]),
            },
        ))
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok([
            self.name.encode()?,
            (self.answer_type as u16).to_be_bytes().to_vec(),
            self.class.to_be_bytes().to_vec(),
            self.ttl.to_be_bytes().to_vec(),
            self.rdlength.to_be_bytes().to_vec(),
            self.rdata.encode().to_vec(),
        ]
        .concat()
        .to_vec())
    }
}

#[derive(Clone, Debug)]
pub enum ResponseData {
    Ipv4([u8; 4]),
}

impl ResponseData {
    pub fn encode(&self) -> &[u8] {
        match self {
            Self::Ipv4(addr) => addr,
        }
    }
}

#[derive(Copy, Debug, Clone)]
#[allow(dead_code)]
pub enum RecordType {
    /// A host address
    A = 1,

    /// An authoratitive name server
    NS = 2,

    /// A mail destination (obselete - use MX)
    MD = 3,

    /// A mail forwarder (obselete - use MX)
    MF = 4,

    /// The canonical name for an alias
    CNAME = 5,

    /// Marks the start of a zone of authority
    SOA = 6,

    /// A mailbox domain name (Experimental)
    MB = 7,

    /// A mail group member (Experimental)
    MG = 8,

    /// A mail rename domain name (Experimental)
    MR = 9,

    /// A null RR (Experimental)
    NULL = 10,

    /// A well known service description
    WKS = 11,

    /// A domain name pointer
    PTR = 12,

    /// Host information
    HINFO = 13,

    /// Mailbox or mail list information
    MINFO = 14,

    /// Mail Exchange
    MX = 15,

    /// Text Strings
    TXT = 16,
}

impl TryFrom<u16> for RecordType {
    type Error = anyhow::Error;

    fn try_from(from: u16) -> anyhow::Result<Self> {
        match from {
            1 => Ok(RecordType::A),
            2 => Ok(RecordType::NS),
            3 => Ok(RecordType::MD),
            4 => Ok(RecordType::MF),
            5 => Ok(RecordType::CNAME),
            6 => Ok(RecordType::SOA),
            7 => Ok(RecordType::MB),
            8 => Ok(RecordType::MG),
            9 => Ok(RecordType::MR),
            10 => Ok(RecordType::NULL),
            11 => Ok(RecordType::WKS),
            12 => Ok(RecordType::PTR),
            13 => Ok(RecordType::HINFO),
            14 => Ok(RecordType::MINFO),
            15 => Ok(RecordType::MX),
            16 => Ok(RecordType::TXT),
            _ => Err(anyhow!("Invalid record type: {}", from)),
        }
    }
}

#[derive(Copy, Debug, Clone)]
pub enum ResponseCode {
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
    Refused = 5,
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
            _ => Err(anyhow!("Invalid response code")),
        }
    }
}

#[derive(Copy, Debug, Clone)]
pub enum Z {
    Always = 0,
}

#[derive(Copy, Debug, Clone)]
pub enum PacketType {
    Query = 0,
    Response = 1,
}

impl TryFrom<u8> for PacketType {
    type Error = anyhow::Error;

    fn try_from(from: u8) -> anyhow::Result<Self> {
        match from {
            0 => Ok(PacketType::Query),
            1 => Ok(PacketType::Response),
            _ => Err(anyhow!("Invalid packet type received: {}", from)),
        }
    }
}

#[derive(Copy, Debug, Clone)]
#[repr(u8)]
pub enum OperationCode {
    /// a standard query (QUERY)
    Query = 0,
    /// an inverse query (IQUERY)
    IQuery = 1,
    /// a server status request (STATUS)
    Status = 2,

    /// Internal invalid representation
    Invalid(u8),
}

impl From<OperationCode> for u8 {
    fn from(from: OperationCode) -> u8 {
        match from {
            OperationCode::Invalid(code) => code,
            OperationCode::Query => 0,
            OperationCode::IQuery => 1,
            OperationCode::Status => 2,
        }
    }
}

impl TryFrom<u8> for OperationCode {
    type Error = anyhow::Error;

    fn try_from(from: u8) -> anyhow::Result<Self> {
        match from {
            0 => Ok(OperationCode::Query),
            1 => Ok(OperationCode::IQuery),
            2 => Ok(OperationCode::Status),
            _ => Ok(OperationCode::Invalid(from)),
        }
    }
}
