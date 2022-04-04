use ureq::Error;
use x509_parser::prelude::*;

fn pin_final_issuer(certs: Option<Vec<Vec<u8>>>) -> Result<(), Error> {
    let err = std::io::Error::new(std::io::ErrorKind::InvalidData, PinError);

    let certs = match certs {
        Some(c) => c,
        None => return Err(err.into()),
    };

    // // log
    // for i in 0..certs.len() {
    //     let certbin = &certs[i];
    //     let (_, cert) = X509Certificate::from_der(certbin).unwrap();
    //     println!("~~ issuer: {}", cert.issuer);
    // }

    let issuers = [
        "C=US, O=Google Trust Services LLC, CN=GTS CA 1C3",
        "C=US, O=Google Trust Services LLC, CN=GTS Root R1",
        "C=BE, O=GlobalSign nv-sa, OU=Root CA, CN=GlobalSign Root CA",
    ];

    let final_cert = X509Certificate::from_der(&certs[0]);
    let final_issuer = match final_cert {
        Ok((_, c)) => c.issuer().to_string(),
        Err(_) => "".to_string(),
    };

    println!("~~ issuer: {} \n~~ expect: {}", final_issuer, issuers[0]);

    if issuers[0] == final_issuer {
        Ok(())
    } else {
        Err(err.into())
    }
}

pub fn main() {
    env_logger::init();

    let agent = ureq::builder().cert_check(pin_final_issuer).build();

    let _ret = agent
        .get("https://www.google.de")
        .call()
        .expect("cant get")
        .into_string()
        .expect("cant stringify");

    // println!("{}", _ret)
}

#[derive(Debug)]
struct PinError;

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cert pinning failed")
    }
}

impl std::error::Error for PinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
