use ocl::builders::DeviceSpecifier;
use ocl::builders::ProgramBuilder;
use ocl::flags::MemFlags;
use ocl::Buffer;
use ocl::Platform;
use ocl::ProQue;
use ocl::Result;

#[derive(Clone, Copy)]
pub struct GpuOptions {
    pub platform_idx: usize,
    pub device_idx: usize,
    pub threads: usize,
    pub local_work_size: Option<usize>,
    pub global_work_size: Option<usize>,
}

pub struct Gpu {
    kernel: ocl::Kernel,
    results: Buffer<u8>,
    keys: Buffer<u8>,
}

impl Gpu {
    pub fn new(opts: GpuOptions) -> Result<Gpu> {
        let mut prog_bldr = ProgramBuilder::new();
        let namespace_qualifier = "#define NAMESPACE_QUALIFIER __private\n";
        prog_bldr
            .source(namespace_qualifier)
            .src(include_str!("../kernel/buffer_structs_template.cl"))
            .src(include_str!("../kernel/sha512.cl"))
            .src(include_str!("../kernel/curve25519-constants.cl"))
            .src(include_str!("../kernel/curve25519-constants2.cl"))
            .src(include_str!("../kernel/curve25519.cl"))
            .src(include_str!("../kernel/entry.cl"));
        let platforms = Platform::list();
        if platforms.is_empty() {
            return Err("No OpenCL platforms exist (check your drivers and OpenCL setup)".into());
        }
        if opts.platform_idx >= platforms.len() {
            return Err(format!(
                "Platform index {} too large (max {})",
                opts.platform_idx,
                platforms.len() - 1
            )
            .into());
        }
        let pro_que = ProQue::builder()
            .prog_bldr(prog_bldr)
            .platform(platforms[opts.platform_idx])
            .device(DeviceSpecifier::Indices(vec![opts.device_idx]))
            .dims(32 * opts.threads)
            .build()?;

        let device = pro_que.device();
        eprintln!("Initializing GPU {} {}", device.vendor()?, device.name()?);

        let results = pro_que
            .buffer_builder::<u8>()
            .flags(MemFlags::new().write_only().host_read_only())
            .build()?;
        let keys = pro_que
            .buffer_builder::<u8>()
            .flags(MemFlags::new().read_only().host_write_only())
            .build()?;

        let kernel = {
            let mut kernel_builder = pro_que.kernel_builder("generate_pubkey");
            kernel_builder
                .global_work_size(opts.threads)
                .arg(&results)
                .arg(&keys);
            if let Some(local_work_size) = opts.local_work_size {
                kernel_builder.local_work_size(local_work_size);
            }
            if let Some(global_work_size) = opts.global_work_size {
                kernel_builder.global_work_size(global_work_size);
            }
            kernel_builder.build()?
        };

        Ok(Gpu {
            kernel,
            results,
            keys,
        })
    }

    pub fn compute(&mut self) -> Result<()> {
        unsafe {
            self.kernel.enq()?;
        }
        Ok(())
    }

    pub fn read_keys(&mut self, results: &mut [u8]) -> Result<()> {
        self.results.read(results).enq()?;
        Ok(())
    }

    pub fn write_seeds(&mut self, keys: &[u8]) -> Result<()> {
        self.keys.write(keys).enq()?;
        Ok(())
    }
}
