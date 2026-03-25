/*
  Lightweight live event feeder for demo dashboards.
  Usage:
    node scripts/live_event_feeder.js --once
    node scripts/live_event_feeder.js
*/

const API_BASE = process.env.API_BASE || "http://localhost:8080";
const USERNAME = process.env.DEMO_USER || "admin";
const PASSWORD = process.env.DEMO_PASS || "admin123";
const INTERVAL_MS = Number(process.env.FEED_INTERVAL_MS || 8000);

function rand(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIp(prefix) {
  return `${prefix}.${rand(1, 254)}`;
}

async function login() {
  const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: USERNAME, password: PASSWORD }),
  });

  if (!res.ok) {
    throw new Error(`Login failed (${res.status})`);
  }

  const payload = await res.json();
  if (!payload?.access_token) {
    throw new Error("Login response missing access_token");
  }

  return payload.access_token;
}

function buildEvent() {
  const riskyPorts = [3389, 445, 22, 139, 5985, 4444];
  const safePorts = [80, 443, 8080, 53];
  const useRisky = Math.random() > 0.3;
  const dstPort = useRisky ? riskyPorts[rand(0, riskyPorts.length - 1)] : safePorts[rand(0, safePorts.length - 1)];

  return {
    src_ip: randomIp("185.220.101"),
    dst_ip: randomIp("10.0.5"),
    dst_port: dstPort,
    protocol: "TCP",
    bytes_sent: rand(50000, 1200000),
    bytes_recv: rand(1000, 300000),
    duration_ms: rand(500, 90000),
    user_agent: "demo-feeder/1.0",
    payload_entropy: Number((Math.random() * 4 + 4).toFixed(2)),
    timestamp: new Date().toISOString(),
  };
}

async function postEvent(token) {
  const body = buildEvent();
  const res = await fetch(`${API_BASE}/api/v1/threats/analyze/network`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });

  return res.status;
}

async function runOnce() {
  const token = await login();
  const statuses = [];
  for (let i = 0; i < 16; i += 1) {
    statuses.push(await postEvent(token));
  }
  console.log("Seeded events. Statuses:", statuses.join(","));
}

async function runLoop() {
  let token = await login();
  console.log(`Feeder started -> ${API_BASE} every ${INTERVAL_MS}ms`);

  setInterval(async () => {
    try {
      let status = await postEvent(token);
      if (status === 401 || status === 403) {
        token = await login();
        status = await postEvent(token);
      }
      process.stdout.write(`feed:${status} `);
    } catch (err) {
      process.stdout.write(`feed:ERR(${err.message}) `);
    }
  }, INTERVAL_MS);
}

(async () => {
  try {
    if (process.argv.includes("--once")) {
      await runOnce();
      return;
    }
    await runLoop();
  } catch (err) {
    console.error("Feeder failed:", err.message);
    process.exit(1);
  }
})();
