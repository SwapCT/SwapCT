use structopt::StructOpt;
use indicatif::{ProgressBar, ProgressStyle};
use omniring::account::{Account, OTAccount};
use omniring::commitment::{Commitment};
use rand::random;
use curve25519_dalek::scalar::Scalar;
use std::time::Instant;
use omniring::transaction::{Transaction, get_test_ring};
use std::fs::File;
use std::io::Write;
use std::collections::HashMap;


#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "SwapCT", about = "Runs the performance tests for SwapCT")]
struct Opt {
    #[structopt(
    short = "s",
    long = "statistics",
    help = "How many repetitions",
    default_value = "3"
    )]
    statistics: u64,

    #[structopt(
    short = "o",
    long = "max-outputs",
    help = "Maximum outputs",
    default_value = "2"
    )]
    outputs: u64,

    #[structopt(
    short = "r",
    long = "ring-size",
    help = "Anonymity ring size: must be 2^n-5, e.g. 11,27,59,123,...",
    default_value = "11"
    )]
    ring: usize,
}

fn main() -> Result<(),std::io::Error> {
    let opt = Opt::from_args();
    println!("using {:?}", opt);

    let acct = Account::new();

    let bar = ProgressBar::new(opt.statistics*opt.outputs);
    bar.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .progress_chars("#>-"));

    let mut time: HashMap<&str,Vec<Vec<u128>>> = vec!["seal","ver"].iter().map(|t|(t.clone(), (0..opt.outputs).map(|_| Vec::new()).collect())).collect();

    for _ in 0..opt.statistics {
        for inouts in 1..opt.outputs+1 {
            bar.inc(1);

            let mut otas = Vec::<OTAccount>::new();
            let mut inamt = 0u64;
            for _ in 0..inouts {
                let r = random::<u64>() % (2u64.pow(40));
                otas.push(acct.derive_ot(&Scalar::from(r)));
                inamt += r;
            }
            let totalin = inamt;

            let mut outs = Vec::<(Account, Scalar)>::new();
            let mut inamt = totalin;
            for _ in 0..(inouts - 1) {
                let r = random::<u64>() % inamt;
                outs.push((acct, Scalar::from(r)));
                inamt -= r;
            }
            outs.push((acct, Scalar::from(inamt)));

            let start = Instant::now();
            let tx = Transaction::spend(&otas,&outs.iter().map(|(a,v)|(a,v)).collect(), &get_test_ring(opt.ring));
            let seal = start.elapsed().as_micros();
            time.get_mut("seal").unwrap()[inouts as usize-1].push(seal);

            let start = Instant::now();
            let v = tx.verify();
            let verify = start.elapsed().as_micros();
            time.get_mut("ver").unwrap()[inouts as usize-1].push(verify);
            assert!(v.is_ok());
        }
    }
    bar.finish();

    let seconds = vec!["seal"];
    let stat: HashMap<&str, Vec<(usize,f32,f32,f32)> > = time.iter().map(|(typ,v)|(typ.clone(),{
        v.iter().enumerate().map(|(i,t)| {
            let mut times = t.clone();
            times.sort();
            let median = times[times.len()/2];
            if seconds.contains(typ) {
                (i+1,(median as f32/1000000f32), (median-times[0])as f32/1000000f32, (times[times.len()-1]-median) as f32/1000000f32)
            }
            else {
                (i+1,(median as f32/1000f32), (median-times[0])as f32/1000f32, (times[times.len()-1]-median) as f32/1000f32)
            }
        }).collect()
    })
    ).collect();

    let genname = String::from("plots/generation.tex");
    let mut genfile = File::create(genname).expect("file not writable");

    let offset = 0.0;

    writeln!(&mut genfile,"\\addplot[only marks,mark=o, red,mark options={{solid}},error bars/.cd,y dir=both,y explicit] coordinates {{")?;
    for g in stat.get("seal").unwrap() {
        writeln!(&mut genfile,"({},{}) -= (0,{}) += (0,{}) ",(g.0 as f32)+offset,g.1,g.2,g.3)?;
    }
    writeln!(&mut genfile,"}}; \\addlegendentry{{Omniring spend, ${}$}};", opt.ring)?;

    let vername = String::from("plots/verification.tex");
    let mut verfile = File::create(vername).expect("file not writable");

    writeln!(&mut verfile,"\\addplot[only marks,mark=triangle*, red,mark options={{solid}},error bars/.cd,y dir=both,y explicit] coordinates {{")?;
    for g in stat.get("ver").unwrap() {
        writeln!(&mut verfile,"({},{}) -= (0,{}) += (0,{}) ",(g.0 as f32)+offset,g.1,g.2,g.3)?;
    }
    writeln!(&mut verfile,"}}; \\addlegendentry{{Omniring VfTx, ${}$}};", opt.ring)?;
    Ok(())
}