/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    smtp::{
        inbound::TestMessage,
        session::{TestSession, VerifyResponse, load_test_message},
    },
    utils::server::TestServerBuilder,
};
use ahash::AHashSet;
use common::{
    config::smtp::session::{Milter, MilterVersion, Stage},
    expr::if_block::IfBlock,
    manager::application::Resource,
};
use http_proto::{ToHttpResponse, request::fetch_body};
use hyper::{body, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use mail_auth::AuthenticatedMessage;
use mail_parser::MessageParser;
use registry::{
    schema::{
        enums::{self, MtaStage},
        prelude::{ObjectType, Property},
        structs::{
            Expression, ExpressionMatch, MtaHook, MtaMilter, MtaStageData, MtaStageRcpt,
            SieveSystemScript,
        },
    },
    types::{list::List, map::Map},
};
use serde::Deserialize;
use smtp::{
    core::SessionData,
    inbound::{
        hooks::{self, Request, SmtpResponse},
        milter::{
            Action, Command, Macros, MilterClient, Modification, Options, Response,
            protocol::*,
            receiver::{FrameResult, Receiver},
        },
    },
};
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

#[derive(Debug, Deserialize)]
struct HeaderTest {
    modifications: Vec<Modification>,
    result: String,
}

#[tokio::test]
async fn milter_session() {
    let mut test = TestServerBuilder::new("smtp_milter_test")
        .await
        .with_http_listener(19014)
        .await
        .capture_queue()
        .disable_services()
        .build()
        .await;

    // Add test settings
    let admin = test.account("admin");
    admin.mta_no_auth().await;
    admin.mta_allow_relaying().await;
    admin
        .registry_create_object(MtaMilter {
            enable: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            host: "localhost".into(), // inbuxa: resolved when the session connects
            port: 9332,
            use_tls: false,
            stages: Map::new(vec![MtaStage::Data]),
            protocol_version: enums::MilterVersion::V6,
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();
    test.expect_reload_settings().await;

    let _rx = spawn_mock_milter_server();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Build session
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.doe.org").await;

    // Test reject
    session
        .send_message(
            "reject@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "503 5.5.3",
        )
        .await;
    test.assert_no_events();

    // Test discard
    session
        .send_message(
            "discard@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    test.assert_no_events();

    // Test temp fail
    session
        .send_message(
            "temp_fail@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "451 4.3.5",
        )
        .await;
    test.assert_no_events();

    // Test shutdown
    session
        .send_message(
            "shutdown@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "421 4.3.0",
        )
        .await;
    test.assert_no_events();

    // Test reply code
    session
        .send_message(
            "reply_code@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "321",
        )
        .await;
    test.assert_no_events();

    // Test accept with header addition
    session
        .send_message(
            "0@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains("X-Hello: World")
        .assert_contains("Subject: Is dinner ready?")
        .assert_contains("Are you hungry yet?");

    // Test accept with header replacement
    session
        .send_message(
            "3@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains("Subject: [SPAM] Saying Hello")
        .assert_count("References: ", 1)
        .assert_contains("Are you hungry yet?");

    // Test accept with body replacement
    session
        .send_message(
            "2@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains("X-Spam: Yes")
        .assert_contains("123456");
}

#[tokio::test]
async fn mta_hook_session() {
    let mut test = TestServerBuilder::new("smtp_mta_hook_test")
        .await
        .with_http_listener(19015)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    // Add test settings
    let admin = test.account("admin");
    admin.mta_no_auth().await;
    admin
        .registry_create_object(MtaStageRcpt {
            allow_relaying: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaHook {
            enable: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            url: "http://127.0.0.1:9333".into(),
            stages: Map::new(vec![MtaStage::Data]),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageData {
            script: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "sender = 'quarantine@doe.org'".into(),
                    then: "'tag_quarantine'".into(),
                }]),
                else_: "false".into(),
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(SieveSystemScript {
            contents: concat!(
                "require [\"editheader\"];\n",
                "addheader \"X-Sieve\" \"Seen\";\n",
                "if exists \"X-Quarantine\" {\n",
                "  deleteheader \"Subject\";\n",
                "  addheader \"Subject\" \"INFECTED\";\n",
                "}\n"
            )
            .into(),
            description: None,
            is_active: true,
            name: "tag_quarantine".into(),
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();
    test.expect_reload_settings().await;

    let _rx = spawn_mock_mta_hook_server();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Build session
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.doe.org").await;

    // Test reject
    session
        .send_message(
            "reject@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "503 5.5.3",
        )
        .await;
    test.assert_no_events();

    // Test discard
    session
        .send_message(
            "discard@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    test.assert_no_events();

    // Test temp fail
    session
        .send_message(
            "temp_fail@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "451 4.3.5",
        )
        .await;
    test.assert_no_events();

    // Test shutdown
    session
        .send_message(
            "shutdown@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "421 4.3.0",
        )
        .await;
    test.assert_no_events();

    // Test reply code
    session
        .send_message(
            "reply_code@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "321",
        )
        .await;
    test.assert_no_events();

    // Test accept with header addition
    session
        .send_message(
            "0@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains("X-Hello: World")
        .assert_contains("Subject: Is dinner ready?")
        .assert_contains("Are you hungry yet?");

    // Test accept with header replacement
    session
        .send_message(
            "3@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains("Subject: [SPAM] Saying Hello")
        .assert_count("References: ", 1)
        .assert_contains("Are you hungry yet?");

    // Test accept with body replacement
    session
        .send_message(
            "2@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains("X-Spam: Yes")
        .assert_contains("123456");

    // Test quarantine
    session
        .send_message(
            "quarantine_only@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains("X-Quarantine: true")
        .assert_contains("Subject: Is dinner ready?")
        .assert_contains("Are you hungry yet?");

    // Test that a DATA stage Sieve script sees and preserves hook modifications
    session
        .send_message(
            "quarantine@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains("X-Quarantine: true")
        .assert_contains("X-Sieve: Seen")
        .assert_contains("Subject: INFECTED")
        .assert_contains("Are you hungry yet?");
}

#[test]
fn milter_address_modifications() {
    let test_message = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("smtp")
            .join("milter")
            .join("message.eml"),
    )
    .unwrap();
    let parsed_test_message = AuthenticatedMessage::parse(test_message.as_bytes()).unwrap();

    let mut data = SessionData::new(
        "127.0.0.1".parse().unwrap(),
        0,
        "127.0.0.1".parse().unwrap(),
        0,
        Default::default(),
        0,
    );

    // ChangeFrom
    assert!(
        data.apply_milter_modifications(
            vec![Modification::ChangeFrom {
                sender: "<>".into(),
                args: "".into(),
            }],
            &parsed_test_message
        )
        .is_none()
    );
    let addr = data.mail_from.as_ref().unwrap();
    assert_eq!(addr.address_lcase, "");
    assert_eq!(addr.dsn_info, None);
    assert_eq!(addr.flags, 0);

    // ChangeFrom with parameters
    assert!(
        data.apply_milter_modifications(
            vec![Modification::ChangeFrom {
                sender: "john@example.org".into(),
                args: "REQUIRETLS ENVID=abc123".into(), //"NOTIFY=SUCCESS,FAILURE ENVID=abc123\n".into()
            }],
            &parsed_test_message
        )
        .is_none()
    );
    let addr = data.mail_from.as_ref().unwrap();
    assert_eq!(addr.address_lcase, "john@example.org");
    assert_ne!(addr.flags, 0);
    assert_eq!(addr.dsn_info, Some("abc123".into()));

    // Add recipients
    assert!(
        data.apply_milter_modifications(
            vec![
                Modification::AddRcpt {
                    recipient: "bill@example.org".into(),
                    args: "".into(),
                },
                Modification::AddRcpt {
                    recipient: "jane@foobar.org".into(),
                    args: "NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;Jane.Doe@Foobar.org".into(),
                },
                Modification::AddRcpt {
                    recipient: "<bill@example.org>".into(),
                    args: "".into(),
                },
                Modification::AddRcpt {
                    recipient: "<>".into(),
                    args: "".into(),
                },
            ],
            &parsed_test_message
        )
        .is_none()
    );
    assert_eq!(data.rcpt_to.len(), 2);
    let addr = data.rcpt_to.first().unwrap();
    assert_eq!(addr.address_lcase, "bill@example.org");
    assert_eq!(addr.dsn_info, None);
    assert_eq!(addr.flags, 0);
    let addr = data.rcpt_to.last().unwrap();
    assert_eq!(addr.address_lcase, "jane@foobar.org");
    assert_ne!(addr.flags, 0);
    assert_eq!(addr.dsn_info, Some("Jane.Doe@Foobar.org".into()));

    // Remove recipients
    assert!(
        data.apply_milter_modifications(
            vec![
                Modification::DeleteRcpt {
                    recipient: "bill@example.org".into(),
                },
                Modification::DeleteRcpt {
                    recipient: "<>".into(),
                },
            ],
            &parsed_test_message
        )
        .is_none()
    );
    assert_eq!(data.rcpt_to.len(), 1);
    let addr = data.rcpt_to.last().unwrap();
    assert_eq!(addr.address_lcase, "jane@foobar.org");
    assert_ne!(addr.flags, 0);
    assert_eq!(addr.dsn_info, Some("Jane.Doe@Foobar.org".into()));
}

#[test]
fn milter_message_modifications() {
    // Read test message
    let milter_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("smtp")
        .join("milter");
    let test_message = fs::read_to_string(milter_path.join("message.eml")).unwrap();
    let tests = serde_json::from_str::<Vec<HeaderTest>>(
        &fs::read_to_string(milter_path.join("message.json")).unwrap(),
    )
    .unwrap();
    let parsed_test_message = AuthenticatedMessage::parse(test_message.as_bytes()).unwrap();
    let mut session_data = SessionData::new(
        "127.0.0.1".parse().unwrap(),
        0,
        "127.0.0.1".parse().unwrap(),
        0,
        Default::default(),
        0,
    );

    for test in tests {
        assert_eq!(
            test.result,
            String::from_utf8(
                session_data
                    .apply_milter_modifications(test.modifications, &parsed_test_message)
                    .unwrap()
            )
            .unwrap()
        )
    }
}

#[test]
fn milter_frame_receiver() {
    let mut stream = Vec::new();

    for i in 0u32..100u32 {
        stream.extend_from_slice((i + 1).to_be_bytes().as_ref());
        stream.push(i as u8);
        for v in 0..i {
            stream.push(v as u8);
        }
    }

    for chunk_size in [stream.len(), 1, 2, 3, 4, 10, 20, 30, 40, 100, 200, 300, 400] {
        let mut receiver = Receiver::with_max_frame_len(100);
        let mut frame_num = 0;

        'outer: for chunk in stream.chunks(chunk_size) {
            loop {
                match receiver.read_frame(chunk) {
                    FrameResult::Frame(bytes) => {
                        /*println!(
                            "frame {frame_num}, chunk: {chunk_size}, {}",
                            if matches!(bytes, std::borrow::Cow::Borrowed(_)) {
                                "borrowed"
                            } else {
                                "owned"
                            }
                        );*/
                        assert_eq!(*bytes.first().unwrap(), frame_num);
                        assert_eq!(bytes.len(), frame_num as usize + 1);
                        frame_num += 1;
                    }
                    FrameResult::Incomplete => continue 'outer,
                    FrameResult::TooLarge(size) => {
                        panic!("Frame too large: {size}")
                    }
                }
            }
        }

        assert_eq!(frame_num, 100, "chunk_size: {}", chunk_size);
    }
}

#[tokio::test]
#[ignore]
async fn milter_client_test() {
    //const PORT : u16 = 11332;
    const PORT: u16 = 7357;
    let mut client = MilterClient::connect(
        &Milter {
            enable: IfBlock::empty(ObjectType::MtaMilter.singleton(), Property::Enable),
            id: ObjectType::MtaMilter.singleton(),
            addrs: vec![SocketAddr::from(([127, 0, 0, 1], PORT))],
            hostname: "localhost".into(),
            port: PORT,
            timeout_connect: Duration::from_secs(10),
            timeout_command: Duration::from_secs(30),
            timeout_data: Duration::from_secs(30),
            tls: false,
            tls_allow_invalid_certs: false,
            tempfail_on_error: false,
            max_frame_len: 5000000,
            protocol_version: MilterVersion::V6,
            flags_actions: None,
            flags_protocol: None,
            run_on_stage: AHashSet::from([Stage::Data]),
        },
        0,
    )
    .await
    .unwrap();
    client.init().await.unwrap();

    let raw_message = load_test_message("arc", "messages");
    let message = MessageParser::new().parse(raw_message.as_bytes()).unwrap();

    let r = client
        .connection(
            "gmail.com",
            "127.0.0.1".parse().unwrap(),
            1235,
            Macros::new(),
        )
        .await
        .unwrap();
    println!("CONNECT: {:?}", r);
    let r = client
        .mail_from("john@gmail.com", None::<&[&str]>, Macros::new())
        .await
        .unwrap();
    println!("MAIL FROM: {:?}", r);
    let r = client
        .rcpt_to("user@gmail.com", None::<&[&str]>, Macros::new())
        .await
        .unwrap();
    println!("RCPT TO: {:?}", r);

    let r = client.data().await.unwrap();
    println!("DATA: {:?}", r);
    let r = client
        .headers(message.headers().iter().map(|header| {
            (
                header.raw_name(),
                std::str::from_utf8(header.raw_value()).unwrap_or_default(),
            )
        }))
        .await
        .unwrap();
    println!("HEADERS: {:?}", r);
    let r = client
        .body(&message.raw()[message.root_part().offset_body() as usize..])
        .await
        .unwrap();
    println!("BODY: {:?}", r);

    client.quit().await.unwrap();
}

pub fn spawn_mock_milter_server() -> watch::Sender<bool> {
    let (tx, rx) = watch::channel(true);
    let tests = Arc::new(
        serde_json::from_str::<Vec<HeaderTest>>(
            &fs::read_to_string(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("resources")
                    .join("smtp")
                    .join("milter")
                    .join("message.json"),
            )
            .unwrap(),
        )
        .unwrap(),
    );

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:9332")
            .await
            .unwrap_or_else(|e| {
                panic!("Failed to bind mock Milter server to 127.0.0.1:9332: {e}");
            });
        let mut rx_ = rx.clone();
        //println!("Mock Milter server listening on port 9332");
        loop {
            tokio::select! {
                stream = listener.accept() => {
                    match stream {
                        Ok((stream, _)) => {
                            tokio::spawn(accept_milter(stream, rx.clone(), tests.clone()));
                        }
                        Err(err) => {
                            panic!("Something went wrong: {err}" );
                        }
                    }
                },
                _ = rx_.changed() => {
                    //println!("Mock Milter server stopping");
                    break;
                }
            };
        }
    });

    tx
}

async fn accept_milter(
    mut stream: TcpStream,
    mut rx: watch::Receiver<bool>,
    tests: Arc<Vec<HeaderTest>>,
) {
    let mut buf = vec![0u8; 1024];
    let mut receiver = Receiver::with_max_frame_len(5000000);
    let mut action = None;
    let mut modifications = None;

    'outer: loop {
        let br = tokio::select! {
            br = stream.read(&mut buf) => {
                match br {
                    Ok(br) => {
                        br
                    }
                    Err(_) => {
                        break;
                    }
                }
            },
            _ = rx.changed() => {
                break;
            }
        };

        if br == 0 {
            break;
        }

        loop {
            match receiver.read_frame(&buf[..br]) {
                FrameResult::Frame(bytes) => {
                    let cmd = deserialize_command(bytes.as_ref());
                    println!("CMD: {cmd}");

                    let response = match cmd {
                        Command::Abort | Command::Macro { .. } => continue,
                        Command::Body { .. }
                        | Command::Data
                        | Command::Connect { .. }
                        | Command::Header { .. }
                        | Command::Helo { .. }
                        | Command::Rcpt { .. }
                        | Command::QuitNewConnection
                        | Command::EndOfHeader => Response::Action(Action::Accept),
                        Command::OptionNegotiation(_) => Response::OptionNegotiation(Options {
                            version: 6,
                            actions: 0,
                            protocol: 0,
                        }),
                        Command::MailFrom { sender, .. } => {
                            let sender = std::str::from_utf8(sender).unwrap();
                            action = match sender
                                .strip_prefix('<')
                                .unwrap()
                                .split_once('@')
                                .unwrap()
                                .0
                            {
                                "accept" => Action::Accept,
                                "reject" => Action::Reject,
                                "discard" => Action::Discard,
                                "temp_fail" => Action::TempFail,
                                "shutdown" => Action::Shutdown,
                                "conn_fail" => Action::ConnectionFailure,
                                "reply_code" => Action::ReplyCode {
                                    code: *b"321",
                                    text: "test".into(),
                                },
                                test_num => {
                                    modifications = tests[test_num.parse::<usize>().unwrap()]
                                        .modifications
                                        .clone()
                                        .into();
                                    Action::Accept
                                }
                            }
                            .into();
                            Response::Action(Action::Accept)
                        }
                        Command::Quit => break 'outer,
                        Command::EndOfBody => {
                            if let Some(modifications) = modifications.take() {
                                for modification in modifications {
                                    // Write modifications
                                    stream
                                        .write_all(&serialize_response(&Response::Modification(
                                            modification,
                                        )))
                                        .await
                                        .unwrap();
                                }
                            }

                            Response::Action(action.take().unwrap())
                        }
                    };

                    // Write response
                    stream
                        .write_all(&serialize_response(&response))
                        .await
                        .unwrap();
                }
                FrameResult::Incomplete => continue 'outer,
                FrameResult::TooLarge(size) => {
                    panic!("Frame too large: {size}")
                }
            }
        }
    }
}

pub fn spawn_mock_mta_hook_server() -> watch::Sender<bool> {
    let (tx, rx) = watch::channel(true);
    let tests = Arc::new(
        serde_json::from_str::<Vec<HeaderTest>>(
            &fs::read_to_string(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("resources")
                    .join("smtp")
                    .join("milter")
                    .join("message.json"),
            )
            .unwrap(),
        )
        .unwrap(),
    );

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:9333")
            .await
            .unwrap_or_else(|e| {
                panic!("Failed to bind mock Milter server to 127.0.0.1:9333: {e}");
            });
        let mut rx_ = rx.clone();
        //println!("Mock jMilter server listening on port 9333");
        loop {
            tokio::select! {
                stream = listener.accept() => {
                    match stream {
                        Ok((stream, _)) => {

                            let _ = http1::Builder::new()
                            .keep_alive(false)
                            .serve_connection(
                                TokioIo::new(stream),
                                service_fn(|mut req: hyper::Request<body::Incoming>| {
                                    let tests = tests.clone();

                                    async move {

                                        let request = serde_json::from_slice::<Request>(&fetch_body(&mut req, 1024 * 1024,0).await.unwrap())
                                        .unwrap();
                                        let response = handle_mta_hook(request, tests);

                                        Ok::<_, hyper::Error>(
                                            Resource::new("application/json", serde_json::to_string(&response).unwrap().into_bytes())
                                            .into_http_response().build(),
                                        )
                                    }
                                }),
                            )
                            .await;
                        }
                        Err(err) => {
                            panic!("Something went wrong: {err}" );
                        }
                    }
                },
                _ = rx_.changed() => {
                    //println!("Mock jMilter server stopping");
                    break;
                }
            };
        }
    });

    tx
}

fn handle_mta_hook(request: Request, tests: Arc<Vec<HeaderTest>>) -> hooks::Response {
    match request
        .envelope
        .unwrap()
        .from
        .address
        .split_once('@')
        .unwrap()
        .0
    {
        "accept" => hooks::Response {
            action: hooks::Action::Accept,
            response: None,
            modifications: vec![],
        },
        "reject" => hooks::Response {
            action: hooks::Action::Reject,
            response: None,
            modifications: vec![],
        },
        "discard" => hooks::Response {
            action: hooks::Action::Discard,
            response: None,
            modifications: vec![],
        },
        "quarantine" | "quarantine_only" => hooks::Response {
            action: hooks::Action::Quarantine,
            response: None,
            modifications: vec![],
        },
        "temp_fail" => hooks::Response {
            action: hooks::Action::Reject,
            response: SmtpResponse {
                status: 451.into(),
                enhanced_status: Some("4.3.5".into()),
                message: Some("Unable to accept message at this time.".into()),
                disconnect: false,
            }
            .into(),
            modifications: vec![],
        },
        "shutdown" => hooks::Response {
            action: hooks::Action::Reject,
            response: SmtpResponse {
                status: 421.into(),
                enhanced_status: Some("4.3.0".into()),
                message: Some("Server shutting down".into()),
                disconnect: false,
            }
            .into(),
            modifications: vec![],
        },
        "conn_fail" => hooks::Response {
            action: hooks::Action::Accept,
            response: SmtpResponse {
                disconnect: true,
                ..Default::default()
            }
            .into(),
            modifications: vec![],
        },
        "reply_code" => hooks::Response {
            action: hooks::Action::Reject,
            response: SmtpResponse {
                status: 321.into(),
                enhanced_status: Some("3.1.1".into()),
                message: Some("Test".into()),
                disconnect: false,
            }
            .into(),
            modifications: vec![],
        },
        test_num => hooks::Response {
            action: hooks::Action::Accept,
            response: None,
            modifications: tests[test_num.parse::<usize>().unwrap()]
                .modifications
                .iter()
                .map(|m| match m {
                    Modification::ChangeFrom { sender, args } => hooks::Modification::ChangeFrom {
                        value: sender.clone(),
                        parameters: args
                            .split_whitespace()
                            .map(|arg| {
                                let (key, value) = arg.split_once('=').unwrap();
                                (key.into(), Some(value.into()))
                            })
                            .collect(),
                    },
                    Modification::AddRcpt { recipient, args } => {
                        hooks::Modification::AddRecipient {
                            value: recipient.clone(),
                            parameters: args
                                .split_whitespace()
                                .map(|arg| {
                                    let (key, value) = arg.split_once('=').unwrap();
                                    (key.into(), Some(value.into()))
                                })
                                .collect(),
                        }
                    }
                    Modification::DeleteRcpt { recipient } => {
                        hooks::Modification::DeleteRecipient {
                            value: recipient.clone(),
                        }
                    }
                    Modification::ReplaceBody { value } => hooks::Modification::ReplaceContents {
                        value: String::from_utf8(value.clone()).unwrap(),
                    },
                    Modification::AddHeader { name, value } => hooks::Modification::AddHeader {
                        name: name.clone(),
                        value: value.clone(),
                    },
                    Modification::InsertHeader { index, name, value } => {
                        hooks::Modification::InsertHeader {
                            index: *index,
                            name: name.clone(),
                            value: value.clone(),
                        }
                    }
                    Modification::ChangeHeader { index, name, value } => {
                        hooks::Modification::ChangeHeader {
                            index: *index,
                            name: name.clone(),
                            value: value.clone(),
                        }
                    }
                    Modification::Quarantine { reason } => hooks::Modification::AddHeader {
                        name: "X-Quarantine".into(),
                        value: reason.clone(),
                    },
                })
                .collect(),
        },
    }
}

// inbuxa: 1.0 dropped the milter codec's server side (Command::deserialize,
// Response::serialize), so the mock milter server carries its own copy.
// Macro contents are skipped: Macros can't be built outside the smtp crate
// and the mock server ignores them.
fn deserialize_command(bytes: &[u8]) -> Command<'_> {
    let mut reader = PacketReader::new(bytes);
    match reader.byte() {
        SMFIC_ABORT => Command::Abort,
        SMFIC_BODY => Command::Body { value: &bytes[1..] },
        SMFIC_BODYEOB => Command::EndOfBody,
        SMFIC_CONNECT => {
            let hostname = reader.read_nul_terminated().unwrap();
            let family = reader.byte();
            let port = reader.read_u16();
            let address = std::str::from_utf8(reader.read_nul_terminated().unwrap()).unwrap();
            Command::Connect {
                hostname,
                port,
                address: match family {
                    b'4' => IpAddr::V4(address.parse().unwrap()),
                    b'6' => IpAddr::V6(address.parse().unwrap()),
                    _ => unreachable!(),
                },
            }
        }
        SMFIC_MACRO => Command::Macro {
            macros: Macros::new(),
        },
        SMFIC_HEADER => {
            let name = reader.read_nul_terminated().unwrap();
            let value = reader.read_nul_terminated().unwrap();
            Command::Header { name, value }
        }
        SMFIC_EOH => Command::EndOfHeader,
        SMFIC_HELO => {
            let hostname = reader.read_nul_terminated().unwrap();
            Command::Helo { hostname }
        }
        SMFIC_MAIL => {
            let sender = reader.read_nul_terminated().unwrap();
            let mut args = Vec::new();
            while let Some(arg) = reader.read_nul_terminated() {
                args.push(arg);
            }
            Command::MailFrom {
                sender,
                args: Some(args),
            }
        }
        SMFIC_RCPT => {
            let recipient = reader.read_nul_terminated().unwrap();
            let mut args = Vec::new();
            while let Some(arg) = reader.read_nul_terminated() {
                args.push(arg);
            }
            Command::Rcpt {
                recipient,
                args: Some(args),
            }
        }
        SMFIC_OPTNEG => Command::OptionNegotiation(Options {
            version: reader.read_u32(),
            actions: reader.read_u32(),
            protocol: reader.read_u32(),
        }),
        SMFIC_QUIT => Command::Quit,
        SMFIC_DATA => Command::Data,
        SMFIC_QUIT_NC => Command::QuitNewConnection,
        c => panic!("Unknown command: {}", char::from(c)),
    }
}

fn build_frame(command: u8, len: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len as usize + 1 + std::mem::size_of::<u32>());
    buf.extend_from_slice((len + 1).to_be_bytes().as_slice());
    buf.push(command);
    buf
}

fn serialize_response(response: &Response) -> Vec<u8> {
    match response {
        Response::Action(action) => match action {
            Action::Accept => build_frame(SMFIR_ACCEPT, 0),
            Action::Continue => build_frame(SMFIR_CONTINUE, 0),
            Action::Discard => build_frame(SMFIR_DISCARD, 0),
            Action::Reject => build_frame(SMFIR_REJECT, 0),
            Action::TempFail => build_frame(SMFIR_TEMPFAIL, 0),
            Action::ReplyCode { code, text } => {
                let mut buf = build_frame(SMFIR_REPLYCODE, text.len() as u32 + 4 + 1);
                buf.extend(code);
                buf.push(b' ');
                buf.extend(text.as_bytes());
                buf.push(0x00);
                buf
            }
            Action::Shutdown => build_frame(SMFIR_SHUTDOWN, 0),
            Action::ConnectionFailure => build_frame(SMFIR_CONN_FAIL, 0),
        },
        Response::Modification(modif) => match modif {
            Modification::ChangeFrom { sender, args } => {
                let mut buf =
                    build_frame(SMFIR_CHGFROM, sender.len() as u32 + args.len() as u32 + 2);
                buf.extend(sender.as_bytes());
                buf.push(0x00);
                buf.extend(args.as_bytes());
                buf.push(0x00);
                buf
            }
            Modification::AddRcpt { recipient, args } => {
                let mut buf = build_frame(
                    SMFIR_ADDRCPT_PAR,
                    recipient.len() as u32 + args.len() as u32 + 2,
                );
                buf.extend(recipient.as_bytes());
                buf.push(0x00);
                buf.extend(args.as_bytes());
                buf.push(0x00);
                buf
            }
            Modification::DeleteRcpt { recipient } => {
                let mut buf = build_frame(SMFIR_DELRCPT, recipient.len() as u32 + 1);
                buf.extend(recipient.as_bytes());
                buf.push(0x00);
                buf
            }
            Modification::ReplaceBody { value } => {
                let mut buf = build_frame(SMFIR_REPLBODY, value.len() as u32);
                buf.extend(value);
                buf
            }
            Modification::AddHeader { name, value } => {
                let mut buf =
                    build_frame(SMFIR_ADDHEADER, name.len() as u32 + value.len() as u32 + 2);
                buf.extend(name.as_bytes());
                buf.push(0x00);
                buf.extend(value.as_bytes());
                buf.push(0x00);
                buf
            }
            Modification::InsertHeader { index, name, value } => {
                let mut buf = build_frame(
                    SMFIR_INSHEADER,
                    name.len() as u32 + value.len() as u32 + std::mem::size_of::<u32>() as u32 + 2,
                );
                buf.extend(index.to_be_bytes().as_slice());
                buf.extend(name.as_bytes());
                buf.push(0x00);
                buf.extend(value.as_bytes());
                buf.push(0x00);
                buf
            }
            Modification::ChangeHeader { index, name, value } => {
                let mut buf = build_frame(
                    SMFIR_CHGHEADER,
                    name.len() as u32 + value.len() as u32 + std::mem::size_of::<u32>() as u32 + 2,
                );
                buf.extend(index.to_be_bytes().as_slice());
                buf.extend(name.as_bytes());
                buf.push(0x00);
                buf.extend(value.as_bytes());
                buf.push(0x00);
                buf
            }
            Modification::Quarantine { reason } => {
                let mut buf = build_frame(SMFIR_QUARANTINE, reason.len() as u32 + 1);
                buf.extend(reason.as_bytes());
                buf.push(0x00);
                buf
            }
        },
        Response::Progress => build_frame(SMFIR_PROGRESS, 0),
        Response::Skip => build_frame(SMFIR_SKIP, 0),
        Response::SetSymbols => build_frame(SMFIR_SETSYMLIST, 0),
        Response::OptionNegotiation(opt) => {
            let mut buf = build_frame(SMFIC_OPTNEG, 3 * std::mem::size_of::<u32>() as u32);
            buf.extend(opt.version.to_be_bytes().as_slice());
            buf.extend(opt.actions.to_be_bytes().as_slice());
            buf.extend(opt.protocol.to_be_bytes().as_slice());
            buf
        }
    }
}

struct PacketReader<'x> {
    bytes: &'x [u8],
    iter: std::iter::Enumerate<std::slice::Iter<'x, u8>>,
}

impl<'x> PacketReader<'x> {
    fn new(bytes: &'x [u8]) -> PacketReader<'x> {
        Self {
            bytes,
            iter: bytes.iter().enumerate(),
        }
    }

    fn byte(&mut self) -> u8 {
        *self.iter.next().unwrap().1
    }

    fn read_nul_terminated(&mut self) -> Option<&'x [u8]> {
        let (start_pos, ch) = self.iter.next()?;
        let mut end_pos = start_pos;

        if *ch != 0x00 {
            loop {
                match self.iter.next().unwrap().1 {
                    0x00 => break,
                    _ => end_pos += 1,
                }
            }
        }

        Some(&self.bytes[start_pos..end_pos + 1])
    }

    fn read_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        for byte in buf.iter_mut() {
            *byte = self.byte();
        }
        u32::from_be_bytes(buf)
    }

    fn read_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        for byte in buf.iter_mut() {
            *byte = self.byte();
        }
        u16::from_be_bytes(buf)
    }
}
