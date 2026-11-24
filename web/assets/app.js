// The interface for the passport tool. Everything of consequence happens in
// the binary; this file collects what the cluster types, shows what came back,
// and builds the printable tag.
(function () {
  "use strict";

  var meta = null;
  var lastIssued = null;

  function el(id) { return document.getElementById(id); }

  function text(tag, value, className) {
    var node = document.createElement(tag);
    node.textContent = value == null ? "" : String(value);
    if (className) { node.className = className; }
    return node;
  }

  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }

  function api(path, body) {
    var options = { headers: { "Accept": "application/json" } };
    if (body !== undefined) {
      options.method = "POST";
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    return fetch(path, options).then(function (response) {
      return response.json().then(function (data) {
        data.httpStatus = response.status;
        return data;
      });
    });
  }

  // ---- theme ----------------------------------------------------------

  // The same toggle the explainer page uses, including the same stored key,
  // so a reader who chose a theme there finds it here. The current theme is
  // whatever the attribute says, or failing that what the system asks for.
  var root = document.documentElement;

  function storedTheme() {
    try { return localStorage.getItem("omsme-theme"); } catch (e) { return null; }
  }

  function currentTheme() {
    var set = root.getAttribute("data-theme");
    if (set) { return set; }
    return (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light";
  }

  function paintThemer(button) {
    if (!button) { return; }
    var dark = currentTheme() === "dark";
    button.textContent = dark ? "☀ Light" : "☾ Dark";
    button.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
  }

  var themer = document.querySelector("[data-themer]");
  if (themer) {
    paintThemer(themer);
    themer.addEventListener("click", function () {
      var next = currentTheme() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("omsme-theme", next); } catch (e) { /* a private window */ }
      paintThemer(themer);
    });
    if (window.matchMedia) {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
        if (!storedTheme()) { paintThemer(themer); }
      });
    }
  }

  // ---- tabs -----------------------------------------------------------

  var tabButtons = Array.prototype.slice.call(document.querySelectorAll("[data-tab]"));
  tabButtons.forEach(function (button) {
    button.addEventListener("click", function () {
      var wanted = button.getAttribute("data-tab");
      tabButtons.forEach(function (other) {
        var name = other.getAttribute("data-tab");
        other.setAttribute("aria-pressed", name === wanted ? "true" : "false");
        el("tab-" + name).hidden = name !== wanted;
      });
      if (wanted === "register") { loadRegister(); }
    });
  });

  // ---- metadata: the choices and the figures come from the binary ------

  function fillSelect(id, values) {
    var select = el(id);
    if (!select) { return; }
    clear(select);
    values.forEach(function (value) {
      var option = document.createElement("option");
      option.value = value.name;
      option.textContent = value.label;
      select.appendChild(option);
    });
  }

  function loadMeta() {
    return api("/api/meta").then(function (data) {
      meta = data;
      fillSelect("role", data.options.role);
      fillSelect("loomType", data.options.loomType);
      fillSelect("article", data.options.article);
      fillSelect("warpFibre", data.options.fibre);
      fillSelect("weftFibre", data.options.fibre);
      fillSelect("zari", data.options.zari);
      fillSelect("binding", data.options.binding);

      var marks = el("marks");
      clear(marks);
      data.options.marks.forEach(function (mark) {
        var label = document.createElement("label");
        var input = document.createElement("input");
        input.type = "checkbox";
        input.value = mark.name;
        input.setAttribute("data-mark", "1");
        label.appendChild(input);
        label.appendChild(text("span", mark.label));
        marks.appendChild(label);
      });

      el("register-count").textContent = "register " + data.registerCount;
      el("key-field").hidden = data.signingKeyLoaded;
      if (data.clusterPublicKey) {
        el("verify-key-hint").textContent =
          "This machine's cluster key is " + data.clusterPublicKey +
          " — but a buyer should use the key the cluster published, not one this machine offered.";
      }
      updateBandHint();
      updateBindingHint();
    });
  }

  // ---- the issuing form ------------------------------------------------

  function collect() {
    var marks = [];
    Array.prototype.slice.call(document.querySelectorAll("[data-mark]")).forEach(function (box) {
      if (box.checked) { marks.push(box.value); }
    });
    return {
      serial: el("serial").value,
      giName: el("giName").value,
      giRegistrationNo: el("giRegistrationNo").value,
      role: el("role").value,
      registerEntryNo: el("registerEntryNo").value,
      cluster: el("cluster").value,
      weaverName: el("weaverName").value,
      weaverId: el("weaverId").value,
      loomNo: el("loomNo").value,
      loomType: el("loomType").value,
      article: el("article").value,
      warpFibre: el("warpFibre").value,
      weftFibre: el("weftFibre").value,
      zari: el("zari").value,
      lengthCm: parseInt(el("lengthCm").value, 10) || 0,
      widthCm: parseInt(el("widthCm").value, 10) || 0,
      offLoomDate: el("offLoomDate").value,
      marks: marks,
      binding: el("binding").value,
      privateKey: el("privateKey").value
    };
  }

  function updateBandHint() {
    if (!meta) { return; }
    var article = el("article").value;
    var hint = el("band-hint");
    var band = null;
    meta.bands.forEach(function (b) {
      meta.options.article.forEach(function (a) {
        if (a.code === b.article && a.name === article) { band = b; }
      });
    });
    if (!band) { hint.textContent = ""; return; }
    hint.textContent = "A " + article.replace(/_/g, " ") + " usually runs " + band.minLengthCm +
      "–" + band.maxLengthCm + " cm by " + band.minWidthCm + "–" + band.maxWidthCm +
      " cm. Outside that you get a warning, not a refusal." + (band.note ? " " + band.note : "");
  }

  function updateBindingHint() {
    var binding = el("binding").value;
    var hint = el("binding-hint");
    if (binding === "not_bound") {
      hint.textContent = "A loose card can be moved to another piece. A buyer checking it learns that the cluster issued a passport, not that this is the cloth it describes.";
    } else {
      hint.textContent = "This is the only thing that ties the passport to this piece of cloth. The signature cannot do it.";
    }
  }

  el("article").addEventListener("change", updateBandHint);
  el("binding").addEventListener("change", updateBindingHint);

  function renderList(container, items, className) {
    if (!items || !items.length) { return; }
    var list = document.createElement("ul");
    list.className = className;
    items.forEach(function (item) { list.appendChild(text("li", item)); });
    container.appendChild(list);
  }

  function showCheck(data) {
    var panel = el("issue-result");
    clear(panel);
    panel.appendChild(text("h2", "Before you sign"));

    if (data.problems && data.problems.length) {
      var bad = document.createElement("div");
      bad.className = "verdict bad";
      bad.appendChild(text("span", "Not ready to sign", "v"));
      bad.appendChild(text("p", data.problems.length + " thing(s) to put right."));
      panel.appendChild(bad);
      renderList(panel, data.problems, "problems");
    } else {
      var good = document.createElement("div");
      good.className = "verdict good";
      good.appendChild(text("span", "Ready to sign", "v"));
      good.appendChild(text("p", "Every rule is satisfied. Nothing has been signed yet."));
      panel.appendChild(good);
    }
    if (data.warnings && data.warnings.length) {
      panel.appendChild(text("h3", "Worth a second look"));
      renderList(panel, data.warnings, "warnings");
    }
  }

  function showIssued(data) {
    lastIssued = data;
    var panel = el("issue-result");
    clear(panel);
    panel.appendChild(text("h2", "The passport"));

    var good = document.createElement("div");
    good.className = "verdict good";
    good.appendChild(text("span", "Signed and filed", "v"));
    good.appendChild(text("p", "Serial " + data.record.serial + ", filed on " + data.record.issuedAt + "."));
    panel.appendChild(good);

    var symbol = document.createElement("div");
    symbol.className = "symbol";
    var img = document.createElement("img");
    img.src = "/api/qr?scale=6&code=" + encodeURIComponent(data.record.code);
    img.alt = "The passport symbol for piece " + data.record.serial;
    symbol.appendChild(img);
    symbol.appendChild(text("span", data.symbol.advice, "caption"));
    panel.appendChild(symbol);

    panel.appendChild(text("h3", "The code on the tag"));
    panel.appendChild(text("div", data.grouped, "code"));

    if (data.warnings && data.warnings.length) {
      panel.appendChild(text("h3", "Worth a second look"));
      renderList(panel, data.warnings, "warnings");
    }

    var row = document.createElement("div");
    row.className = "btnrow";
    var printButton = text("button", "Print the tag", "btn primary");
    printButton.type = "button";
    printButton.addEventListener("click", function () { printTag(data); });
    row.appendChild(printButton);
    var checkButton = text("button", "Check it as a buyer would", "btn ghost");
    checkButton.type = "button";
    checkButton.addEventListener("click", function () {
      el("verify-code").value = data.record.code;
      el("verify-key").value = "";
      tabButtons.forEach(function (b) { if (b.getAttribute("data-tab") === "verify") { b.click(); } });
    });
    row.appendChild(checkButton);
    panel.appendChild(row);

    panel.appendChild(text("p", "Sew the tag into the piece. Until it is fastened to the cloth, this passport describes a piece rather than this piece.", "note"));
  }

  function printTag(data) {
    var sheet = el("tagsheet");
    clear(sheet);
    var tag = document.createElement("div");
    tag.className = "tag";

    var img = document.createElement("img");
    img.src = "/api/qr?scale=8&code=" + encodeURIComponent(data.record.code);
    img.alt = "";
    tag.appendChild(img);

    tag.appendChild(text("h2", data.record.giName));
    var dl = document.createElement("dl");
    [
      ["Serial", data.record.serial],
      ["Weaver", data.record.weaverName + " · loom " + data.record.loomNo],
      ["Cluster", data.record.cluster],
      ["Woven", data.record.described.loomType],
      ["Fibre", "warp " + data.record.described.warpFibre + ", weft " + data.record.described.weftFibre],
      ["Off the loom", data.record.offLoomDate + " · " + data.record.lengthCm + " cm by " + data.record.widthCm + " cm"],
      ["Marks claimed", data.record.described.marks],
      ["GI registration", data.record.giRegistrationNo]
    ].forEach(function (pair) {
      dl.appendChild(text("dt", pair[0]));
      dl.appendChild(text("dd", pair[1]));
    });
    tag.appendChild(dl);

    tag.appendChild(text("div", data.grouped, "codeblock"));
    tag.appendChild(text("p",
      "Scan the symbol or type the code, then check it against this cluster's published key: " +
      data.record.issuerPublicKey +
      ". A valid signature shows the cluster issued this passport and that it has not been altered. It does not show that this is the cloth described — that is what this tag being sewn in is for.",
      "how"));

    sheet.appendChild(tag);
    sheet.hidden = false;
    // Give the browser a moment to fetch the symbol before the dialogue opens.
    window.setTimeout(function () { window.print(); }, 350);
  }

  el("check-btn").addEventListener("click", function () {
    api("/api/check", collect()).then(showCheck);
  });

  el("issue-form").addEventListener("submit", function (event) {
    event.preventDefault();
    api("/api/issue", collect()).then(function (data) {
      if (data.problems && data.problems.length) {
        showCheck(data);
        return;
      }
      if (data.error) {
        showCheck({ problems: [data.error] });
        return;
      }
      showIssued(data);
      loadMeta();
    });
  });

  el("sample-btn").addEventListener("click", function () {
    el("serial").value = "KSS-2026-004128";
    el("giName").value = "Kanchipuram Silk";
    el("giRegistrationNo").value = "";
    el("registerEntryNo").value = "";
    el("cluster").value = "Kanchipuram Silk Weavers Co-op Society";
    el("weaverName").value = "R. Saravanan";
    el("weaverId").value = "HWID-33-004128";
    el("loomNo").value = "L-27";
    el("lengthCm").value = "823";
    el("widthCm").value = "120";
    el("offLoomDate").value = meta ? meta.today : "";
    el("article").value = "saree";
    el("loomType").value = "handloom";
    el("warpFibre").value = "silk";
    el("weftFibre").value = "silk";
    el("zari").value = "pure_zari";
    el("binding").value = "sewn_tag";
    updateBandHint();
    updateBindingHint();
    showCheck({ problems: [
      "The registration number and the register entry are deliberately left empty: they are yours to supply, and this tool ships no list of registrations it could fill in for you."
    ] });
  });

  // ---- checking a passport --------------------------------------------

  function factRow(table, label, value) {
    var row = document.createElement("tr");
    row.appendChild(text("th", label));
    row.appendChild(text("td", value));
    table.appendChild(row);
  }

  function showVerdict(panel, result) {
    var box = document.createElement("div");
    if (result.pass) {
      box.className = "verdict good";
      box.appendChild(text("span", result.boundToPiece ? "Signed by this cluster" : "Signed, but not fastened to the cloth", "v"));
    } else if (result.passport) {
      box.className = "verdict bad";
      box.appendChild(text("span", "Not confirmed", "v"));
    } else {
      box.className = "verdict unknown";
      box.appendChild(text("span", "This is not a passport code", "v"));
    }
    box.appendChild(text("p", result.reason));
    panel.appendChild(box);
  }

  function showVerify(data) {
    var result = data.result;
    var panel = el("verify-result");
    clear(panel);
    panel.appendChild(text("h2", "What the check says"));
    showVerdict(panel, result);

    if (result.passport) {
      var facts = document.createElement("table");
      facts.className = "facts";
      var p = result.passport;
      var d = result.described;
      factRow(facts, "Piece serial", p.serial);
      factRow(facts, "Geographical indication", p.giName + " · registration " + p.giRegistrationNo);
      factRow(facts, "Issued by", d.role + " · entry " + p.registerEntryNo);
      factRow(facts, "Cluster", p.cluster);
      factRow(facts, "Weaver", p.weaverName + " (" + p.weaverId + ") · loom " + p.loomNo);
      factRow(facts, "Woven", d.loomType);
      factRow(facts, "Article", d.article + " · " + p.lengthCm + " cm by " + p.widthCm + " cm");
      factRow(facts, "Fibre", "warp " + d.warpFibre + ", weft " + d.weftFibre);
      factRow(facts, "Zari", d.zari);
      factRow(facts, "Off the loom", p.offLoomDate + (result.age ? " · " + result.age : ""));
      factRow(facts, "Marks claimed", d.marks);
      factRow(facts, "Fastened to the piece by", d.binding);
      factRow(facts, "Signed with the key", p.issuerPublicKey);
      panel.appendChild(facts);

      var state = [];
      state.push(result.selfConsistent
        ? "The code is internally consistent: its signature matches the key printed inside it. That alone means nothing — a forger signs their own code with their own key."
        : "The code's signature does not even match the key inside it, so the code is damaged rather than forged.");
      if (result.checkedAgainst) {
        state.push(result.keyMatch
          ? "It was signed by the key you supplied."
          : "It was signed by some other key than the one you supplied.");
      } else {
        state.push("No key was supplied to check against.");
      }
      if (data.inThisRegister) {
        state.push("This machine's own register holds the same code. " + data.registerRemark);
      }
      renderList(panel, state, "limits");
    }

    if (result.inconsistencies && result.inconsistencies.length) {
      panel.appendChild(text("h3", "This passport contradicts itself"));
      renderList(panel, result.inconsistencies, "problems");
    }

    if (result.physicalChecks && result.physicalChecks.length) {
      panel.appendChild(text("h3", "Now check the cloth"));
      var list = document.createElement("ul");
      list.className = "checklist";
      result.physicalChecks.forEach(function (check) {
        var item = document.createElement("li");
        item.appendChild(text("span", check.do, "do"));
        item.appendChild(text("span", check.why, "why"));
        list.appendChild(item);
      });
      panel.appendChild(list);
    }

    panel.appendChild(text("h3", "What this check does not establish"));
    renderList(panel, result.limits, "limits");
  }

  el("verify-btn").addEventListener("click", function () {
    api("/api/verify", {
      code: el("verify-code").value,
      clusterPublicKey: el("verify-key").value
    }).then(function (data) {
      if (data.error) {
        var panel = el("verify-result");
        clear(panel);
        panel.appendChild(text("h2", "What the check says"));
        panel.appendChild(text("p", data.error, "note"));
        return;
      }
      showVerify(data);
    });
  });

  el("verify-clear").addEventListener("click", function () {
    el("verify-code").value = "";
    el("verify-key").value = "";
    var panel = el("verify-result");
    clear(panel);
    panel.appendChild(text("h2", "What the check says"));
    panel.appendChild(text("p", "Paste a code and the cluster's key.", "note"));
  });

  // ---- the register ----------------------------------------------------

  function loadRegister() {
    api("/api/register").then(function (data) {
      var body = el("register-table").querySelector("tbody");
      clear(body);
      (data.records || []).forEach(function (record) {
        var row = document.createElement("tr");
        row.appendChild(text("td", record.issuedAt));
        row.appendChild(text("td", record.serial));
        row.appendChild(text("td", record.giName + " · " + record.described.article));
        row.appendChild(text("td", record.weaverName));
        row.appendChild(text("td", record.loomNo));
        row.appendChild(text("td", record.lengthCm + "×" + record.widthCm, "num"));
        body.appendChild(row);
      });
      el("register-empty").hidden = (data.count || 0) > 0;
      el("register-count").textContent = "register " + (data.count || 0);
    });
  }

  // ---- keys ------------------------------------------------------------

  el("newkey-btn").addEventListener("click", function () {
    api("/api/keys", {}).then(function (data) {
      var panel = el("key-result");
      clear(panel);
      if (data.error) {
        panel.appendChild(text("p", data.error, "note"));
        return;
      }
      panel.appendChild(text("h3", "Publish this — the public key"));
      panel.appendChild(text("div", data.publicKey, "code keyout"));
      panel.appendChild(text("h3", "Keep this — the private key"));
      panel.appendChild(text("div", data.privateKey, "code keyout"));
      panel.appendChild(text("p", data.warning, "note"));
    });
  });

  loadMeta();
})();
