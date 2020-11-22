use structopt::StructOpt;
use indicatif::{ProgressBar, ProgressStyle};
use swapct::account::{Account, OTAccount};
use swapct::commitment::{TypeCommitment, Type};
use rand::random;
use curve25519_dalek::scalar::Scalar;
use std::time::Instant;
use swapct::offer::{Offer, get_test_ring};
use std::fs::File;
use std::io::Write;


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
    let typ = TypeCommitment::type_gen(&String::from("mytype"));

    let bar = ProgressBar::new(opt.statistics*opt.outputs);
    bar.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .progress_chars("#>-"));

    let mut time_gen: Vec<Vec<u128>> = (0..opt.outputs).map(|_| Vec::new()).collect();
    let mut time_ver: Vec<Vec<u128>> = (0..opt.outputs).map(|_| Vec::new()).collect();

    for _ in 0..opt.statistics {
        for inouts in 1..opt.outputs+1 {
            bar.inc(1);

            let mut otas = Vec::<OTAccount>::new();
            let mut inamt = 0u64;
            for _ in 0..inouts {
                let r = random::<u64>() % (2u64.pow(40));
                otas.push(acct.derive_ot(&typ, &Scalar::from(r)));
                inamt += r;
            }
            let totalin = inamt;

            let mut outs = Vec::<(Account, Type, Scalar)>::new();
            let mut inamt = totalin;
            for _ in 0..(inouts - 1) {
                let r = random::<u64>() % inamt;
                outs.push((acct, typ, Scalar::from(r)));
                inamt -= r;
            }
            outs.push((acct, typ, Scalar::from(inamt)));

            let start = Instant::now();
            let off = Offer::offer(&otas, &outs.iter().map(|(a,t,v)|(a,t,v)).collect(), &vec![get_test_ring(opt.ring); otas.len()]);
            let tx = off.seal(None);
            let gen = start.elapsed().as_micros();
            time_gen[inouts as usize-1].push(gen);

            let start = Instant::now();
            let v = tx.verify();
            let verify = start.elapsed().as_micros();
            time_ver[inouts as usize-1].push(verify);
            assert!(v.is_ok());
        }
    }
    bar.finish();

    let stat_gen: Vec<(usize,f32,f32,f32)> = time_gen.iter().enumerate().map(|(i,t)| {
        let mut times = t.clone();
        times.sort();
        let median = times[times.len()/2];
        (i+1,(median as f32/1000000f32), (median-times[0])as f32/1000000f32, (times[times.len()-1]-median) as f32/1000000f32)
    }).collect();
    let stat_ver: Vec<(usize,u128,u128,u128)> = time_ver.iter().enumerate().map(|(i,t)| {
        let mut times = t.clone();
        times.sort();
        let median = times[times.len()/2];
        (i+1,median/1000, (median-times[0])/1000, (times[times.len()-1]-median)/1000)
    }).collect();

    let genname = String::from("plots/generation.tex");
    let mut genfile = File::create(genname).expect("file not writable");

    writeln!(&mut genfile,"\\addplot[only marks,mark=triangle*, red,mark options={{solid}},error bars/.cd,y dir=both,y explicit] coordinates {{")?;
    for g in stat_gen {
        writeln!(&mut genfile,"({},{}) -= (0,{}) += (0,{}) ",g.0,g.1,g.2,g.3)?;
    }
    writeln!(&mut genfile,"}}; \\addlegendentry{{SwapCT, ${}$, you}};", opt.ring)?;

    let vername = String::from("plots/verification.tex");
    let mut verfile = File::create(vername).expect("file not writable");

    writeln!(&mut verfile,"\\addplot[only marks,mark=triangle*, red,mark options={{solid}},error bars/.cd,y dir=both,y explicit] coordinates {{")?;
    for g in stat_ver {
        writeln!(&mut verfile,"({},{}) -= (0,{}) += (0,{}) ",g.0,g.1,g.2,g.3)?;
    }
    writeln!(&mut verfile,"}}; \\addlegendentry{{SwapCT, ${}$, you}};", opt.ring)?;
    Ok(())
}