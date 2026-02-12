/* opnDossier Diff Report - Minimal JS for interactivity */
document.addEventListener("DOMContentLoaded", function() {
  // Expand/collapse all sections
  var toggle = document.getElementById("toggle-all");
  if (toggle) {
    toggle.addEventListener("click", function() {
      var details = document.querySelectorAll("details.section");
      var allOpen = Array.from(details).every(function(d) { return d.open; });
      details.forEach(function(d) { d.open = !allOpen; });
      toggle.textContent = allOpen ? "Expand All" : "Collapse All";
    });
  }

  // Filter by change type
  var filters = document.querySelectorAll(".filter-btn");
  filters.forEach(function(btn) {
    btn.addEventListener("click", function() {
      var type = btn.dataset.type;
      var rows = document.querySelectorAll(".changes-table tr[data-type]");
      if (btn.classList.contains("active")) {
        btn.classList.remove("active");
        rows.forEach(function(r) { r.style.display = ""; });
      } else {
        filters.forEach(function(f) { f.classList.remove("active"); });
        btn.classList.add("active");
        rows.forEach(function(r) {
          r.style.display = r.dataset.type === type ? "" : "none";
        });
      }
    });
  });
});
