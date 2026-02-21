(function updateCartBadge() {
  try {
    const raw = document.cookie
      .split("; ")
      .find((c) => c.startsWith("shopvuln_cart="));
    if (!raw) return;
    const json = decodeURIComponent(raw.split("=").slice(1).join("="));
    const cart = JSON.parse(json);
    const items = cart.Items || cart.items || [];
    const count = items.reduce(
      (s, i) => s + (i.Quantity || i.quantity || 0),
      0,
    );
    const badge = document.getElementById("cartBadge");
    if (badge && count > 0) {
      badge.textContent = count;
      badge.style.display = "";
    }
  } catch {
  }
})();

document.querySelectorAll(".alert-dismissible").forEach((el) => {
  setTimeout(() => {
    const bsAlert = bootstrap?.Alert?.getOrCreateInstance?.(el);
    bsAlert?.close();
  }, 4000);
});
