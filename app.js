
(() => {
  "use strict";

  const DB_KEY = "WASL_DEMO_DATABASE_V1";
  const SESSION_KEY = "WASL_DEMO_SESSION";

  const emptyDB = {
    clients: [],
    businesses: [],
    services: [],
    orders: []
  };

  const loadDB = () => {
    try {
      return { ...emptyDB, ...JSON.parse(localStorage.getItem(DB_KEY) || "{}") };
    } catch {
      return { ...emptyDB };
    }
  };

  let db = loadDB();

  const saveDB = () => {
    localStorage.setItem(DB_KEY, JSON.stringify(db));
  };

  const getSession = () => {
    try {
      return JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
    } catch {
      return null;
    }
  };

  const setSession = user =>
    localStorage.setItem(SESSION_KEY, JSON.stringify(user));

  const logout = () => {
    localStorage.removeItem(SESSION_KEY);
    location.reload();
  };

  const id = () => crypto.randomUUID();

  const hashPassword = async password => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits({
      name: "PBKDF2",
      salt,
      iterations: 120000,
      hash: "SHA-256"
    }, key, 256);

    const hex = bytes => Array.from(bytes)
      .map(b => b.toString(16).padStart(2, "0")).join("");

    return { salt: hex(salt), hash: hex(new Uint8Array(bits)) };
  };

  const verifyPassword = async (password, saved) => {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits({
      name: "PBKDF2",
      salt: new Uint8Array(saved.salt.match(/.{2}/g).map(x => parseInt(x, 16))),
      iterations: 120000,
      hash: "SHA-256"
    }, key, 256);

    return Array.from(new Uint8Array(bits))
      .map(b => b.toString(16).padStart(2, "0")).join("") === saved.hash;
  };

  const escapeHTML = value => String(value ?? "").replace(
    /[&<>"']/g,
    c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;",
      '"': "&quot;", "'": "&#39;"
    })[c]
  );

  const style = document.createElement("style");
  style.textContent = `
    .wasl-box{background:white;color:#14243a;border-radius:16px;
      padding:20px;margin:18px 0;box-shadow:0 5px 20px #00000010}
    .wasl-box h2,.wasl-box h3{margin-bottom:12px}
    .wasl-box input,.wasl-box select,.wasl-box textarea{
      width:100%;padding:12px;margin:7px 0 13px;border:1px solid #cbd5e1;
      border-radius:9px;font-size:15px;background:white;color:#14243a}
    .wasl-box button{padding:12px 18px;border:0;border-radius:9px;
      background:#1264c5;color:white;font-weight:bold;cursor:pointer;margin:5px}
    .wasl-muted{color:#718096;font-size:13px;line-height:1.8}
    .wasl-item{padding:12px;border-bottom:1px solid #e5eaf0;line-height:1.8}
    .wasl-success{color:#087b50;font-weight:bold}
    .wasl-error{color:#bd3030;font-weight:bold}
    .wasl-gold{background:#d6b56d!important;color:#172438!important}
    .wasl-table{width:100%;border-collapse:collapse;font-size:13px}
    .wasl-table td,.wasl-table th{padding:10px;border-bottom:1px solid #40516a;text-align:right}
    .wasl-admin{background:#19263a;color:white}
    .wasl-admin .wasl-item{border-color:#40516a}
  `;
  document.head.appendChild(style);

  const message = (text, success = false) =>
    `<p class="${success ? "wasl-success" : "wasl-error"}">${escapeHTML(text)}</p>`;

  const emailExists = email =>
    db.clients.some(x => x.email === email) ||
    db.businesses.some(x => x.email === email);

  // ================= CLIENT PORTAL =================

  async function initClient() {
    const account = document.querySelector(".account");
    if (!account) return;

    function showAuth(mode = "register", msg = "") {
      account.innerHTML = `
        <div class="wasl-box">
          <h2>حسابك في وصل</h2>
          <p class="wasl-muted">أنشئ حسابك أو سجل الدخول للمتابعة.</p>
          <div>
            <button type="button" id="clientRegisterTab">حساب جديد</button>
            <button type="button" id="clientLoginTab">تسجيل الدخول</button>
          </div>
          <form id="clientAuth">
            <div id="clientNameField">
              <label>الاسم الكامل</label>
              <input name="name" required placeholder="اسمك الكامل">
              <label>رقم الهاتف</label>
              <input name="phone" required placeholder="رقم الهاتف">
            </div>
            <label>البريد الإلكتروني</label>
            <input name="email" type="email" required placeholder="البريد الإلكتروني">
            <label>كلمة المرور</label>
            <input name="password" type="password" minlength="8" required placeholder="8 أحرف على الأقل">
            <button type="submit" class="wasl-gold" id="clientSubmit">إنشاء الحساب</button>
            <div id="clientMessage">${msg}</div>
          </form>
        </div>`;

      let currentMode = mode;
      const nameField = account.querySelector("#clientNameField");
      const submit = account.querySelector("#clientSubmit");

      const changeMode = m => {
        currentMode = m;
        nameField.style.display = m === "register" ? "block" : "none";
        nameField.querySelectorAll("input").forEach(x => x.required = m === "register");
        submit.textContent = m === "register" ? "إنشاء الحساب" : "تسجيل الدخول";
      };

      account.querySelector("#clientRegisterTab").onclick = () => changeMode("register");
      account.querySelector("#clientLoginTab").onclick = () => changeMode("login");
      changeMode(mode);

      account.querySelector("#clientAuth").onsubmit = async e => {
        e.preventDefault();
        const f = new FormData(e.target);
        const email = String(f.get("email")).trim().toLowerCase();
        const password = String(f.get("password"));
        const box = account.querySelector("#clientMessage");

        if (currentMode === "register") {
          if (emailExists(email)) {
            box.innerHTML = message("هذا البريد مسجل من قبل.");
            return;
          }

          const user = {
            id: id(),
            name: String(f.get("name")).trim(),
            phone: String(f.get("phone")).trim(),
            email,
            password: await hashPassword(password),
            createdAt: new Date().toISOString()
          };

          db.clients.push(user);
          saveDB();
          setSession({ role: "client", id: user.id, name: user.name });
          renderClient();
        } else {
          const user = db.clients.find(x => x.email === email);
          if (!user || !(await verifyPassword(password, user.password))) {
            box.innerHTML = message("البريد الإلكتروني أو كلمة المرور غير صحيحة.");
            return;
          }
          setSession({ role: "client", id: user.id, name: user.name });
          renderClient();
        }
      };
    }

    function renderClient() {
      const session = getSession();
      const user = db.clients.find(x => x.id === session?.id);
      if (!user) {
        showAuth();
        return;
      }

      const available = [
        { name: "خدمات الصيانة", icon: "🔧" },
        { name: "النقل والتوصيل", icon: "🚚" },
        { name: "الخدمات المنزلية", icon: "🏠" },
        { name: "التجارة والتسوق", icon: "🛍️" },
        { name: "خدمات أخرى", icon: "✨" }
      ];

      db.businesses.filter(b => b.status === "approved").forEach(b => {
        db.services.filter(s => s.businessId === b.id).forEach(s => {
          available.push({ name: s.name, icon: "🏢" });
        });
      });

      const orders = db.orders.filter(o => o.clientId === user.id);

      account.innerHTML = `
        <div class="wasl-box">
          <h2>مرحباً ${escapeHTML(user.name)}</h2>
          <p class="wasl-muted">${escapeHTML(user.email)}</p>
          <button id="clientLogout">تسجيل الخروج</button>
        </div>
        <div class="wasl-box">
          <h2>استكشاف الخدمات</h2>
          <form id="clientOrder">
            <label>اختر الخدمة</label>
            <select name="service" required>
              <option value="">اختر خدمة</option>
              ${available.map(s => `<option>${escapeHTML(s.name)}</option>`).join("")}
            </select>
            <label>تفاصيل الطلب</label>
            <textarea name="details" required placeholder="اشرح ما تحتاجه"></textarea>
            <button type="submit">إرسال الطلب</button>
            <div id="orderMessage"></div>
          </form>
        </div>
        <div class="wasl-box">
          <h2>طلباتي (${orders.length})</h2>
          ${orders.length ? orders.map(o => `
            <div class="wasl-item">
              <strong>${escapeHTML(o.service)}</strong>
              <p>${escapeHTML(o.details)}</p>
              <p>الحالة: ${escapeHTML(o.status)}</p>
            </div>`).join("") : '<p class="wasl-muted">لا توجد طلبات حتى الآن.</p>'}
        </div>`;

      account.querySelector("#clientLogout").onclick = logout;

      account.querySelector("#clientOrder").onsubmit = e => {
        e.preventDefault();
        const f = new FormData(e.target);
        db.orders.push({
          id: id(),
          clientId: user.id,
          service: f.get("service"),
          details: f.get("details"),
          status: "جديد",
          createdAt: new Date().toISOString()
        });
        saveDB();
        renderClient();
      };
    }

    const session = getSession();
    if (session?.role === "client") renderClient();
    else showAuth();
  }

  // ================= BUSINESS PORTAL =================

  function initBusiness() {
    const form = document.getElementById("businessForm");
    if (!form) return;

    const main = document.querySelector("main");
    const passwordLabel = document.createElement("label");
    passwordLabel.textContent = "كلمة مرور الحساب";
    const passwordInput = document.createElement("input");
    passwordInput.type = "password";
    passwordInput.name = "password";
    passwordInput.required = true;
    passwordInput.minLength = 8;
    passwordInput.placeholder = "8 أحرف على الأقل";
    form.querySelector("button[type=submit]").before(passwordLabel, passwordInput);

    const emailInput = form.querySelector('[name="email"]');
    if (emailInput) emailInput.required = true;

    const login = document.createElement("section");
    login.className = "panel";
    login.innerHTML = `
      <h2>لديك حساب مؤسسة؟</h2>
      <form id="businessLogin">
        <label>البريد الإلكتروني</label>
        <input name="email" type="email" required placeholder="البريد الإلكتروني">
        <label>كلمة المرور</label>
        <input name="password" type="password" required>
        <button type="submit">تسجيل الدخول</button>
        <div id="businessLoginMessage"></div>
      </form>`;
    form.parentElement.before(login);

    function dashboard(business) {
      login.style.display = "none";
      form.parentElement.style.display = "none";

      let panel = document.getElementById("businessDashboard");
      if (!panel) {
        panel = document.createElement("section");
        panel.id = "businessDashboard";
        panel.className = "panel";
        main.appendChild(panel);
      }

      const services = db.services.filter(s => s.businessId === business.id);

      panel.innerHTML = `
        <h2>مرحباً ${escapeHTML(business.company)}</h2>
        <p>حالة طلب الانضمام: <strong>${business.status === "approved" ? "مقبول" : "قيد المراجعة"}</strong></p>
        <button id="businessLogout">تسجيل الخروج</button>
        <hr style="margin:20px 0;opacity:.2">
        <h3>إضافة خدمة</h3>
        <form id="addBusinessService">
          <label>اسم الخدمة</label>
          <input name="name" required placeholder="اسم الخدمة">
          <label>وصف الخدمة</label>
          <input name="description" required placeholder="وصف مختصر">
          <button type="submit">إضافة الخدمة</button>
        </form>
        <h3>خدمات مؤسستك</h3>
        ${services.length ? services.map(s => `
          <div class="wasl-item">${escapeHTML(s.name)} — ${escapeHTML(s.description)}</div>
        `).join("") : "<p>لم تضف خدمات بعد.</p>"}
      `;

      panel.querySelector("#businessLogout").onclick = logout;
      panel.querySelector("#addBusinessService").onsubmit = e => {
        e.preventDefault();
        const f = new FormData(e.target);
        db.services.push({
          id: id(),
          businessId: business.id,
          name: f.get("name"),
          description: f.get("description")
        });
        saveDB();
        dashboard(business);
      };
    }

    form.addEventListener("submit", async e => {
      e.preventDefault();
      e.stopImmediatePropagation();

      const f = new FormData(form);
      const email = String(f.get("email")).trim().toLowerCase();

      if (emailExists(email)) {
        alert("هذا البريد الإلكتروني مسجل من قبل.");
        return;
      }

      const business = {
        id: id(),
        company: f.get("company"),
        manager: f.get("manager"),
        phone: f.get("phone"),
        email,
        activity: f.get("activity"),
        address: f.get("address"),
        details: f.get("details"),
        password: await hashPassword(String(f.get("password"))),
        status: "pending",
        createdAt: new Date().toISOString()
      };

      db.businesses.push(business);
      saveDB();
      setSession({ role: "business", id: business.id, name: business.company });
      dashboard(business);
    }, true);

    login.querySelector("#businessLogin").onsubmit = async e => {
      e.preventDefault();
      const f = new FormData(e.target);
      const email = String(f.get("email")).trim().toLowerCase();
      const business = db.businesses.find(b => b.email === email);
      const msg = login.querySelector("#businessLoginMessage");

      if (!business || !(await verifyPassword(String(f.get("password")), business.password))) {
        msg.innerHTML = message("بيانات الدخول غير صحيحة.");
        return;
      }

      setSession({ role: "business", id: business.id, name: business.company });
      dashboard(business);
    };

    const session = getSession();
    if (session?.role === "business") {
      const business = db.businesses.find(b => b.id === session.id);
      if (business) dashboard(business);
    }
  }

  // ================= ADMIN PORTAL =================

  function initAdmin() {
    const main = document.querySelector("main");
    if (!main) return;

    const gate = document.createElement("section");
    gate.className = "panel";
    gate.style.cssText = "max-width:500px;margin:35px auto;padding:25px;background:#19263a;color:white;border:1px solid #40516a;border-radius:16px";
    gate.innerHTML = `
      <h2>دخول مدير المنصة</h2>
      <p>الدخول التجريبي للإدارة</p>
      <form id="adminLogin">
        <label>البريد الإلكتروني</label>
        <input name="email" type="email" required placeholder="البريد الإلكتروني">
        <label>كلمة المرور</label>
        <input name="password" type="password" required placeholder="كلمة المرور">
        <button type="submit">دخول الإدارة</button>
        <p id="adminMessage" class="notice"></p>
      </form>
      <p class="notice">بيانات العرض التجريبي: admin@wasl.demo</p>
    `;
    main.before(gate);
    main.style.display = "none";

    function dashboard() {
      gate.style.display = "none";
      main.style.display = "block";

      const stats = main.querySelectorAll(".stat strong");
      if (stats[0]) stats[0].textContent = db.clients.length;
      if (stats[1]) stats[1].textContent = db.businesses.length;
      if (stats[2]) stats[2].textContent = db.orders.filter(o => o.status === "جديد").length;

      let panel = document.getElementById("waslAdminData");
      if (!panel) {
        panel = document.createElement("section");
        panel.id = "waslAdminData";
        panel.className = "panel wasl-admin";
        main.appendChild(panel);
      }

      panel.innerHTML = `
        <h2>إدارة بيانات وصل</h2>
        <button id="adminLogout">تسجيل الخروج</button>

        <h3 style="margin-top:25px">طلبات انضمام المؤسسات</h3>
        ${db.businesses.length ? db.businesses.map(b => `
          <div class="wasl-item">
            <strong>${escapeHTML(b.company)}</strong>
            <p>المسؤول: ${escapeHTML(b.manager)}</p>
            <p>النشاط: ${escapeHTML(b.activity)}</p>
            <p>الهاتف: ${escapeHTML(b.phone)}</p>
            <p>الحالة: ${b.status === "approved" ? "مقبولة" : "قيد المراجعة"}</p>
            ${b.status !== "approved" ? `<button data-approve="${b.id}">قبول المؤسسة</button>` : ""}
          </div>
        `).join("") : "<p>لا توجد مؤسسات مسجلة.</p>"}

        <h3 style="margin-top:25px">العملاء المسجلون</h3>
        ${db.clients.length ? db.clients.map(c => `
          <div class="wasl-item">${escapeHTML(c.name)} — ${escapeHTML(c.email)} — ${escapeHTML(c.phone)}</div>
        `).join("") : "<p>لا يوجد عملاء مسجلون.</p>"}

        <h3 style="margin-top:25px">طلبات العملاء</h3>
        ${db.orders.length ? db.orders.map(o => `
          <div class="wasl-item">
            <strong>${escapeHTML(o.service)}</strong>
            <p>${escapeHTML(o.details)}</p>
            <p>الحالة: ${escapeHTML(o.status)}</p>
            <select data-order="${o.id}">
              ${["جديد","قيد المعالجة","مكتمل","مرفوض"].map(s =>
                `<option ${o.status === s ? "selected" : ""}>${s}</option>`
              ).join("")}
            </select>
          </div>
        `).join("") : "<p>لا توجد طلبات حتى الآن.</p>"}
      `;

      panel.querySelector("#adminLogout").onclick = logout;

      panel.querySelectorAll("[data-approve]").forEach(button => {
        button.onclick = () => {
          const b = db.businesses.find(x => x.id === button.dataset.approve);
          if (b) b.status = "approved";
          saveDB();
          dashboard();
        };
      });

      panel.querySelectorAll("[data-order]").forEach(select => {
        select.onchange = () => {
          const o = db.orders.find(x => x.id === select.dataset.order);
          if (o) o.status = select.value;
          saveDB();
          dashboard();
        };
      });
    }

    gate.querySelector("#adminLogin").onsubmit = e => {
      e.preventDefault();
      const f = new FormData(e.target);
      if (
        f.get("email").trim().toLowerCase() === "admin@wasl.demo" &&
        f.get("password") === "WaslAdmin2026!"
      ) {
        setSession({ role: "admin", id: "demo-admin", name: "مدير وصل" });
        dashboard();
      } else {
        gate.querySelector("#adminMessage").textContent = "بيانات الدخول غير صحيحة.";
      }
    };

    if (getSession()?.role === "admin") dashboard();
  }

  const path = location.pathname.toLowerCase();

  if (path.includes("/client/")) initClient();
  else if (path.includes("/business/")) initBusiness();
  else if (path.includes("/admin/")) initAdmin();

})();
