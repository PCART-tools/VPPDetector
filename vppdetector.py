## @package vppdetector
#  Standalone command-line entry point for VPP scanning.
#
#
#  Run the packaged command-line interface from a source checkout.
#  从源码目录运行包内的命令行接口。



from vppdetector.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
