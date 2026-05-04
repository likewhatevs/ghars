# rust-script recipes for ghars

# Print mutation score from last run
[script("rust-script")]
mutants-score:
    //! ```cargo
    //! [dependencies]
    //! serde = { version = "1", features = ["derive"] }
    //! serde_json = "1"
    //! ```
    #[derive(serde::Deserialize)]
    struct Lab { caught: usize, missed: usize, timeout: usize }
    fn main() {
        let path = "mutants.out/outcomes.json";
        let body = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => { println!("no {path}; skipping score computation"); return; }
        };
        let lab: Lab = serde_json::from_str(&body).unwrap();
        let denom = lab.caught + lab.missed + lab.timeout;
        if denom == 0 { println!("0 mutants generated"); return; }
        let score = lab.caught * 100 / denom;
        println!("Mutation score: {score}% ({} caught, {} missed, {} timeout)",
                 lab.caught, lab.missed, lab.timeout);
    }
