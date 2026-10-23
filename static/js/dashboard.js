/**
 * SecureLogin AI - Frontend Helpers & Security Interactivity
 */

document.addEventListener("DOMContentLoaded", function () {
  console.log("SecureLogin AI SOC Telemetry Engine Initialized.");

  // Auto-dismiss alerts after 6 seconds
  const alerts = document.querySelectorAll(".alert-dismissible");
  alerts.forEach(function (alert) {
    setTimeout(function () {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      if (bsAlert) {
        bsAlert.close();
      }
    }, 6000);
  });
});
