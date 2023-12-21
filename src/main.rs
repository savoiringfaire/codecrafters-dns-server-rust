use anyhow::Context;
use dns_starter_rust::{Answer, OperationCode, Packet, PacketType, ResponseCode};
use std::{
    collections::HashMap,
    env,
    net::{SocketAddr, UdpSocket},
};

struct Request {
    source: SocketAddr,
    request: Packet,

    received_responses: Vec<Packet>,
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut upstream = "8.8.8.8:53";

    if args.len() == 3 {
        upstream = args[2].as_str();
    }

    let udp_socket = UdpSocket::bind("0.0.0.0:2053").context("Failed to bind to address")?;
    let upstream: SocketAddr = upstream.parse()?;
    let mut buf = [0; 512];

    let mut request_map: HashMap<u16, Request> = HashMap::new();
    let mut next_id: u16 = 0;

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let packet = buf.clone();
                let req: Packet = Packet::try_from(&packet[..])?;

                match req.header.packet_type {
                    PacketType::Query => {
                        let packet_id = next_id;
                        next_id += 1;

                        println!(
                            "Incoming query id: {}, our outgoing id: {}",
                            req.header.id, packet_id
                        );

                        request_map.insert(
                            packet_id,
                            Request {
                                received_responses: Vec::with_capacity(req.questions.len()),
                                request: req,
                                source,
                            },
                        );
                        let incoming_request = &request_map[&packet_id].request;

                        for question in &incoming_request.questions {
                            let upstream_request =
                                Packet::new(packet_id, PacketType::Query, ResponseCode::Success)
                                    .with_question(question.clone());

                            println!("Forwarding query");
                            udp_socket
                                .send_to(&upstream_request.encode()?, upstream)
                                .expect("Failed to send response");
                        }
                    }

                    PacketType::Response => {
                        println!("Incoming Response for id: {}", req.header.id);
                        let original_request = &mut request_map.get_mut(&req.header.id);

                        match original_request {
                            Some(ref mut original_request) => {
                                original_request.received_responses.push(req.clone());

                                if original_request.received_responses.len() as u16
                                    == original_request.request.header.question_count
                                {
                                    println!(
                                        "Received all expected answers for {}",
                                        original_request.request.header.id
                                    );

                                    let response_code = match original_request.request.header.opcode
                                    {
                                        OperationCode::Query => ResponseCode::Success,
                                        _ => ResponseCode::NotImplemented,
                                    };

                                    let response = Packet::new(
                                        original_request.request.header.id,
                                        PacketType::Response,
                                        response_code,
                                    )
                                    .with_questions(&mut req.questions.clone())
                                    .with_answers(
                                        &mut original_request
                                            .received_responses
                                            .clone()
                                            .into_iter()
                                            .map(|response| response.answers)
                                            .flatten()
                                            .collect::<Vec<Answer>>(),
                                    )
                                    .with_opcode(original_request.request.header.opcode)
                                    .with_recursion_desired(
                                        original_request.request.recursion_desired(),
                                    )
                                    .encode()?;

                                    udp_socket
                                        .send_to(&response, original_request.source)
                                        .expect("Failed to send response");
                                } else {
                                    println!(
                                        "Still waiting for {} answers for {}",
                                        original_request.request.header.question_count
                                            - original_request.received_responses.len() as u16,
                                        original_request.request.header.id
                                    );
                                }
                            }
                            None => {
                                println!("Unexpected packet ID received: {}", req.header.id)
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }

    Ok(())
}
