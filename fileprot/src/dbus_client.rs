use anyhow::{self as ah, Context};
use fileprot_common::dbus_interface::AccessControlProxy;
use zbus::Connection;

/// Connect to the daemon's D-Bus service on the system bus.
pub async fn connect() -> ah::Result<AccessControlProxy<'static>> {
    let connection = Connection::system()
        .await
        .context("failed to connect to system D-Bus")?;
    AccessControlProxy::new(&connection)
        .await
        .context("failed to create D-Bus proxy")
}
