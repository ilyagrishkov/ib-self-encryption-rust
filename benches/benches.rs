extern crate ib_self_encryption_rust;

#[cfg(test)]
mod benches {
    use std::{env, fs};
    use std::fs::File;
    use std::io::Write;
    use std::time::Instant;
    use ib_self_encryption_rust::rustgo::return_string;
    use ib_self_encryption_rust::self_encrypt;

    #[test]
    fn bench_100kb() {
        let directory = format!("{}/benches/resources/100KB", env::current_dir().unwrap().to_str().unwrap());
        let path = return_string(String::from(directory));
        let identity = return_string(String::from("randomidentity"));

        let n = 100;

        let mut results = vec![];
        for _ in 0..n {
            let now = Instant::now();
            {
                self_encrypt(path, identity);
            }
            let elapsed = now.elapsed();
            results.push(elapsed.as_secs_f32())
        }

        fs::create_dir_all("benches/output").unwrap();
        let json = serde_json::to_string(&results).unwrap();
        let mut file = File::create("benches/output/100KB.json").unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }

    #[test]
    fn bench_250kb() {
        let directory = format!("{}/benches/resources/250KB", env::current_dir().unwrap().to_str().unwrap());
        let path = return_string(String::from(directory));
        let identity = return_string(String::from("randomidentity"));

        let n = 100;

        let mut results = vec![];
        for _ in 0..n {
            let now = Instant::now();
            {
                self_encrypt(path, identity);
            }
            let elapsed = now.elapsed();
            results.push(elapsed.as_secs_f32())
        }

        fs::create_dir_all("benches/output").unwrap();
        let json = serde_json::to_string(&results).unwrap();
        let mut file = File::create("benches/output/250KB.json").unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }

    #[test]
    fn bench_500kb() {
        let directory = format!("{}/benches/resources/500KB", env::current_dir().unwrap().to_str().unwrap());
        let path = return_string(String::from(directory));
        let identity = return_string(String::from("randomidentity"));

        let n = 100;

        let mut results = vec![];
        for _ in 0..n {
            let now = Instant::now();
            {
                self_encrypt(path, identity);
            }
            let elapsed = now.elapsed();
            results.push(elapsed.as_secs_f32())
        }

        fs::create_dir_all("benches/output").unwrap();
        let json = serde_json::to_string(&results).unwrap();
        let mut file = File::create("benches/output/500KB.json").unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }

    #[test]
    fn bench_750kb() {
        let directory = format!("{}/benches/resources/750KB", env::current_dir().unwrap().to_str().unwrap());
        let path = return_string(String::from(directory));
        let identity = return_string(String::from("randomidentity"));

        let n = 100;

        let mut results = vec![];
        for _ in 0..n {
            let now = Instant::now();
            {
                self_encrypt(path, identity);
            }
            let elapsed = now.elapsed();
            results.push(elapsed.as_secs_f32())
        }

        fs::create_dir_all("benches/output").unwrap();
        let json = serde_json::to_string(&results).unwrap();
        let mut file = File::create("benches/output/750KB.json").unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }

    #[test]
    fn bench_1mb() {
        let directory = format!("{}/benches/resources/1MB", env::current_dir().unwrap().to_str().unwrap());
        let path = return_string(String::from(directory));
        let identity = return_string(String::from("randomidentity"));

        let n = 100;

        let mut results = vec![];
        for _ in 0..n {
            let now = Instant::now();
            {
                self_encrypt(path, identity);
            }
            let elapsed = now.elapsed();
            results.push(elapsed.as_secs_f32())
        }

        fs::create_dir_all("benches/output").unwrap();
        let json = serde_json::to_string(&results).unwrap();
        let mut file = File::create("benches/output/1MB.json").unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }

    #[test]
    fn bench_10mb() {
        let directory = format!("{}/benches/resources/10MB", env::current_dir().unwrap().to_str().unwrap());
        let path = return_string(String::from(directory));
        let identity = return_string(String::from("randomidentity"));

        let n = 100;

        let mut results = vec![];
        for _ in 0..n {
            let now = Instant::now();
            {
                self_encrypt(path, identity);
            }
            let elapsed = now.elapsed();
            results.push(elapsed.as_secs_f32())
        }

        fs::create_dir_all("benches/output").unwrap();
        let json = serde_json::to_string(&results).unwrap();
        let mut file = File::create("benches/output/10MB.json").unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }

    #[test]
    fn bench_25mb() {
        let directory = format!("{}/benches/resources/25MB", env::current_dir().unwrap().to_str().unwrap());
        let path = return_string(String::from(directory));
        let identity = return_string(String::from("randomidentity"));

        let n = 100;

        let mut results = vec![];
        for _ in 0..n {
            let now = Instant::now();
            {
                self_encrypt(path, identity);
            }
            let elapsed = now.elapsed();
            results.push(elapsed.as_secs_f32())
        }

        fs::create_dir_all("benches/output").unwrap();
        let json = serde_json::to_string(&results).unwrap();
        let mut file = File::create("benches/output/25MB.json").unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }

    #[test]
    fn bench_50mb() {
        let directory = format!("{}/benches/resources/50MB", env::current_dir().unwrap().to_str().unwrap());
        let path = return_string(String::from(directory));
        let identity = return_string(String::from("randomidentity"));

        let n = 100;

        let mut results = vec![];
        for _ in 0..n {
            let now = Instant::now();
            {
                self_encrypt(path, identity);
            }
            let elapsed = now.elapsed();
            results.push(elapsed.as_secs_f32())
        }

        fs::create_dir_all("benches/output").unwrap();
        let json = serde_json::to_string(&results).unwrap();
        let mut file = File::create("benches/output/50MB.json").unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }

    #[test]
    fn bench_75mb() {
        let directory = format!("{}/benches/resources/75MB", env::current_dir().unwrap().to_str().unwrap());
        let path = return_string(String::from(directory));
        let identity = return_string(String::from("randomidentity"));

        let n = 100;

        let mut results = vec![];
        for _ in 0..n {
            let now = Instant::now();
            {
                self_encrypt(path, identity);
            }
            let elapsed = now.elapsed();
            results.push(elapsed.as_secs_f32())
        }

        fs::create_dir_all("benches/output").unwrap();
        let json = serde_json::to_string(&results).unwrap();
        let mut file = File::create("benches/output/75MB.json").unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }

    #[test]
    fn bench_100mb() {
        let directory = format!("{}/benches/resources/100MB", env::current_dir().unwrap().to_str().unwrap());
        let path = return_string(String::from(directory));
        let identity = return_string(String::from("randomidentity"));

        let n = 100;

        let mut results = vec![];
        for _ in 0..n {
            let now = Instant::now();
            {
                self_encrypt(path, identity);
            }
            let elapsed = now.elapsed();
            results.push(elapsed.as_secs_f32())
        }

        fs::create_dir_all("benches/output").unwrap();
        let json = serde_json::to_string(&results).unwrap();
        let mut file = File::create("benches/output/100MB.json").unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }
}

