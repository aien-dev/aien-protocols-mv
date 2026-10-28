// Cross-check: Core PR #662 task.rs (verbatim, sha256 recorded) oracle+run digests for hex payloads on stdin lines.
#[allow(dead_code)]
mod task;
use std::io::BufRead;
use std::sync::atomic::AtomicBool;
fn main() {
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let b: Vec<u8> = (0..line.len()).step_by(2).map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap()).collect();
        let spec = task::TaskSpec::decode(&b).unwrap();
        let o = task::oracle(&spec);
        let cancel = AtomicBool::new(false);
        let ctl = task::Control { cancel: &cancel, deadline: std::time::Instant::now() + std::time::Duration::from_secs(600), threads: 1 };
        let r = task::run(&spec, &ctl).ok().unwrap();
        assert_eq!(o, r);
        println!("{}", o.iter().map(|x| format!("{x:02x}")).collect::<String>());
    }
}
