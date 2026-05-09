use std::io;
use std::env;

fn main() {
    let increment: u16;
    match env::var("INCREMENT"){
        Ok(val) => {increment = val.trim().parse::<u16>().expect("Please use a number as the increment\n");},Err(_) => {increment = 0;}
    }
    let mut counter: u16 = 1;
    loop {
        let mut buff = String::new();
        println!("Press ENTER to count up!");
        io::stdin().read_line(&mut buff).expect("Failed to read line");
        counter += increment;
        println!("Counter: {}", counter);
        match counter {
            0 => {println!("HEY! HOWD YOU BREAK MY COUNTER?");break;}
            n if (1..=65535).contains(&n) => continue,
            _ => {["Max count reached!"].iter().for_each(|&msg| println!("{}", msg));break;}
        }
    }
}
