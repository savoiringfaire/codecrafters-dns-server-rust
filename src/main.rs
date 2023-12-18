use std::net::UdpSocket;
use dns_starter_rust::{
    Packet,
    Header,
    Question,
    Answer,
    PacketType,
    RecordType,
    OperationCode,
    ResponseCode,
    ResponseData,
    Z
};

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
                let response = Packet {
                    header: Header {
                        id: req.header.id,
                        packet_type: PacketType::Response,
                        opcode: req.header.opcode,
                        authoratitive_answer: false,
                        truncation: false,
                        recursion_desired: req.header.recursion_desired,
                        recursion_available: false,
                        z: Z::Always,
                        response_code: match req.header.opcode {
                            OperationCode::Query => ResponseCode::Success,
                            _ => ResponseCode::NotImplemented,
                        },
                        question_count: req.header.question_count,
                        answer_count: req.header.question_count,
                        name_server_count: 0,
                        additional_records_count: 0,
                    },
                    questions: req.questions.clone(),
                    answers: req
                        .questions
                        .clone()
                        .into_iter()
                        .map(|question| {
                            Answer {
                                name: question.name.clone(),
                                answer_type: RecordType::A,
                                class: 1,
                                ttl: 60,
                                // TODO: Encode properly
                                rdlength: 4,
                                rdata: ResponseData::Ipv4([0x08, 0x08, 0x08, 0x08]),
                            }
                        })
                        .collect(),
                }
                .encode()?;

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
