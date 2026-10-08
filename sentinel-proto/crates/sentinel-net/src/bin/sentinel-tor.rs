//! The Tor process for phones (see `sentinel_net::torchild`): shipped
//! inside the Android app as `libsentinel_tor.so`, so the system unpacks it
//! where the app may run it.

fn main() {
    sentinel_net::torchild::child_main()
}
