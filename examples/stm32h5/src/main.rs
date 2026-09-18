#![no_std]
#![no_main]

use defmt::*;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_net::StackStorage;
use embassy_net::tcp::TcpSocket;
use embassy_net::wire::Ipv4Address;
use embassy_stm32::eth::{Ethernet, GenericPhy, PacketQueue, Sma};
use embassy_stm32::peripherals::{ETH, ETH_SMA};
use embassy_stm32::rcc::{
    AHBPrescaler, APBPrescaler, Hse, HseMode, Pll, PllDiv, PllMul, PllPreDiv, PllSource, Sysclk,
    VoltageScale,
};
use embassy_stm32::time::Hertz;
use embassy_stm32::{Config, bind_interrupts, eth};
use embassy_time::Timer;
use embedded_io_async::Write;
use embedded_tls::{Aes128GcmSha256, NoVerify, TlsConfig, TlsConnection, TlsContext};
use panic_probe as _;
use static_cell::StaticCell;

use embassy_crypto_rustcrypto as _;

bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler<ETH>;
});

type Device = Ethernet<'static, ETH, GenericPhy<Sma<'static, ETH_SMA>>>;

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static>) -> ! {
    runner.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) -> ! {
    let mut config = Config::default();
    config.rcc.hsi = None;
    config.rcc.hsi48 = Some(Default::default()); // needed for RNG
    config.rcc.hse = Some(Hse {
        freq: Hertz(8_000_000),
        mode: HseMode::BypassDigital,
    });
    config.rcc.pll1 = Some(Pll {
        source: PllSource::Hse,
        prediv: PllPreDiv::Div2,
        mul: PllMul::Mul125,
        divp: Some(PllDiv::Div2),
        divq: Some(PllDiv::Div2),
        divr: None,
    });
    config.rcc.ahb_pre = AHBPrescaler::Div1;
    config.rcc.apb1_pre = APBPrescaler::Div1;
    config.rcc.apb2_pre = APBPrescaler::Div1;
    config.rcc.apb3_pre = APBPrescaler::Div1;
    config.rcc.sys = Sysclk::Pll1P;
    config.rcc.voltage_scale = VoltageScale::Scale0;
    let p = embassy_stm32::init(config);
    info!("Hello World!");

    // Generate random seed, served by the RNG peripheral through the
    // embassy-crypto driver.
    let mut seed = [0; 8];
    embassy_crypto::rng_fill_bytes(&mut seed);
    let seed = u64::from_le_bytes(seed);

    let mac_addr = [0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];

    static PACKETS: StaticCell<PacketQueue<4, 4>> = StaticCell::new();
    let device = Ethernet::new(
        PACKETS.init(PacketQueue::<4, 4>::new()),
        p.ETH,
        p.PA1,
        p.PA7,
        p.PC4,
        p.PC5,
        p.PG13,
        p.PB15,
        p.PG11,
        mac_addr,
        p.ETH_SMA,
        p.PA2,
        p.PC1,
        Irqs,
    );

    static STACK: StaticCell<StackStorage> = StaticCell::new();
    let (stack, runner) = embassy_net::Stack::new(STACK.init(StackStorage::new()), seed);

    static DEVICE: StaticCell<Device> = StaticCell::new();
    let iface = unwrap!(stack.add_iface(DEVICE.init(device)));
    iface.set_dhcpv4(Some(Default::default()));

    spawner.spawn(unwrap!(net_task(runner)));

    iface.wait_config_up().await;

    info!("Network initialized");

    let mut rx_buffer = [0; 4096];
    let mut tx_buffer = [0; 4096];
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];

    loop {
        let mut socket = unwrap!(TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer));

        socket.set_timeout(Some(embassy_time::Duration::from_secs(10)));

        let remote_endpoint = (Ipv4Address::new(192, 168, 69, 100), 12345);
        info!("connecting...");
        if let Err(e) = socket.connect(remote_endpoint).await {
            info!("connect error: {:?}", e);
            Timer::after_secs(3).await;
            continue;
        }
        info!("TCP connected!");

        let config = TlsConfig::new().with_server_name("example.com");
        let mut tls: TlsConnection<_, Aes128GcmSha256> =
            TlsConnection::new(socket, &mut read_record_buffer, &mut write_record_buffer);

        if let Err(e) = tls.open(TlsContext::new(&config, NoVerify)).await {
            info!("TLS handshake error: {:?}", e);
            Timer::after_secs(3).await;
            continue;
        }
        info!("TLS connected!");

        if let Err(e) = tls.write_all(b"ping").await {
            info!("TLS write error: {:?}", e);
            Timer::after_secs(3).await;
            continue;
        }
        if let Err(e) = tls.flush().await {
            info!("TLS flush error: {:?}", e);
            Timer::after_secs(3).await;
            continue;
        }

        let mut rx_buf = [0; 128];
        match tls.read(&mut rx_buf[..]).await {
            Ok(sz) => info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]),
            Err(e) => info!("TLS read error: {:?}", e),
        }

        if let Err((_, e)) = tls.close().await {
            info!("TLS close error: {:?}", e);
        }
        Timer::after_secs(3).await;
    }
}
