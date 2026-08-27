use super::utils::get_hostname;
use crate::exporters::*;
use crate::sensors::Sensor;
use std::time::Duration;

pub struct Warp10Exporter {
    metric_generator: MetricGenerator,

    client: warp10::Client,

    write_token: String,

    step: Duration,
}

#[derive(clap::Args, Debug)]
pub struct ExporterArgs {

    #[arg(short = 'H', long, default_value = "localhost")]
    pub host: String,

    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,

    #[arg(short = 'S', long, default_value = "http")]
    pub scheme: String,

    #[arg(short = 't', long)]
    pub write_token: Option<String>,

    #[arg(short, long, value_name = "SECONDS", default_value_t = 2)]
    pub step: u64,

    #[arg(short, long)]
    pub qemu: bool,
}

const TOKEN_ENV_VAR: &str = "SCAPH_WARP10_WRITE_TOKEN";

impl Exporter for Warp10Exporter {

    fn run(&mut self) {
        loop {
            match self.iterate() {
                Ok(res) => debug!("Result: {:?}", res),
                Err(err) => error!("Failed ! {:?}", err),
            }
            std::thread::sleep(self.step);
        }
    }

    fn kind(&self) -> &str {
        "warp10"
    }
}

impl Warp10Exporter {

    pub fn new(sensor: &dyn Sensor, args: ExporterArgs) -> Warp10Exporter {

        let topology = sensor
            .get_topology()
            .expect("sensor topology should be available");
        let metric_generator = MetricGenerator::new(topology, get_hostname(), args.qemu, false);

        let scheme = args.scheme;
        let host = args.host;
        let port = args.port;
        let client = warp10::Client::new(&format!("{scheme}://{host}:{port}"))
            .expect("warp10 Client could not be created");
        let write_token = args.write_token.unwrap_or_else(|| {
            std::env::var(TOKEN_ENV_VAR).unwrap_or_else(|_| panic!("No token found, you must provide either --write-token or the env var {TOKEN_ENV_VAR}"))
        });

        Warp10Exporter {
            metric_generator,
            client,
            write_token,
            step: Duration::from_secs(args.step),
        }
    }

    pub fn iterate(&mut self) -> Result<Vec<warp10::Warp10Response>, warp10::Error> {
        let writer = self.client.get_writer(self.write_token.clone());
        self.metric_generator
            .topology
            .proc_tracker
            .clean_terminated_process_records_vectors();

        debug!("Refreshing topology.");
        self.metric_generator.topology.refresh();

        self.metric_generator.gen_all_metrics();

        let mut process_data: Vec<warp10::Data> = vec![];

        for metric in self.metric_generator.pop_metrics() {
            let mut labels = vec![];

            for (k, v) in &metric.attributes {
                labels.push(warp10::Label::new(k, v));
            }

            process_data.push(warp10::Data::new(
                time::OffsetDateTime::now_utc(),
                None,
                metric.name,
                labels,
                warp10::Value::String(metric.metric_value.to_string().replace('`', "")),
            ));
        }

        let res = writer.post_sync(process_data)?;

        let results = vec![res];

        Ok(results)
    }
}
