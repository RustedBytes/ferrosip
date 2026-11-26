-- m14-lua-routing: the routing decisions, called from routes/main.fsr as
-- lua.run("route_<tenant>", <From display name>).
--
-- Each worker thread has its own Lua state: globals such as `calls` are
-- per worker, never shared between workers, and start again from zero
-- when the script is reloaded (ferroctl app_lua.reload).

VERSION = "v1"

-- Which Lua state this is (random per state; math.random is seeded per state).
local STATE = string.format("%08x", math.random(0, 0x7fffffff))
calls = 0

local PBX = os.getenv("PBX") or "sip:127.0.0.1:5070"
local GATEWAY = os.getenv("GATEWAY") or "sip:127.0.0.1:5080"
local BLOCKED = { spammer = true, robocall = true }

local function stamp()
  calls = calls + 1
  KSR.hdr.append("X-Lua-State: " .. STATE .. "\r\n")
  KSR.hdr.append("X-Lua-Count: " .. calls .. "\r\n")
  KSR.hdr.append("X-Lua-Version: " .. VERSION .. "\r\n")
end

local function reject(code, reason)
  KSR.sl.sl_send_reply(code, reason)
  KSR.x.exit()
end

function route_default(display)
  stamp()
  local user = KSR.pv.gete("$rU")
  -- Deliberate failures, for the edge cases.
  if user == "boom" then
    error("deliberate error for " .. user)
  elseif user == "nilindex" then
    local t = nil
    return t.field
  elseif user == "badksr" then
    return KSR.nosuch.no_such_function("x")
  end
  if BLOCKED[KSR.pv.gete("$fU")] then
    reject(403, "Blocked by Lua")
  end
  -- The display name (any UTF-8) and its length in bytes.
  if display ~= nil and display ~= "" then
    KSR.hdr.append("X-Caller-Name: " .. display .. "\r\n")
    KSR.hdr.append("X-Caller-Name-Bytes: " .. #display .. "\r\n")
  end
  local note = KSR.pv.get("$hdr(X-Note)")
  if note ~= nil then
    KSR.hdr.append("X-Note-Echo: " .. note .. " (" .. #note .. " bytes)\r\n")
  end
  if user:match("^%+?%d+$") then
    KSR.pv.sets("$du", GATEWAY)
    KSR.hdr.append("X-Lua-Route: gateway\r\n")
  elseif user == "sales" or user == "support" then
    KSR.pv.sets("$du", PBX)
    KSR.hdr.append("X-Lua-Route: pbx\r\n")
  else
    reject(404, "No route in Lua")
  end
  return 1
end

-- Tenant acme: everything to the PBX.
function route_acme(display)
  stamp()
  KSR.pv.sets("$du", PBX)
  KSR.hdr.append("X-Lua-Route: acme-pbx\r\n")
  return 1
end

-- Tenant closed: Lua says no by returning false (the .fsr answers 500).
function route_closed(display)
  stamp()
  return false
end
