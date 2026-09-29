#pragma once

// Luau compatibility layer injected after the C APIs exist.
// Makes common hub scripts not explode
// on missing globals. Soft-hooks only — no hidden HTTP, no cookies, no RAT.

namespace vt {

inline constexpr char kInitScript[] = R"LUA(
local ok, err = pcall(function()
    local G = getgenv and getgenv() or _G
    local function wrap(name, fn)
        if type(fn) == "function" then
            G[name] = fn
            if rawset then pcall(rawset, _G, name, fn) end
        end
    end

    wrap("identifyexecutor", identifyexecutor or function() return "VoidTrace", "0.3.0" end)
    wrap("getexecutorname", getexecutorname or function() return "VoidTrace" end)
    wrap("checkcaller", checkcaller or function() return true end)
    wrap("getgenv", getgenv or function() return G end)
    wrap("getrenv", getrenv or function() return _G end)
    wrap("getreg", getreg or function() return {} end)

    if not G.loadstring and loadstring then wrap("loadstring", loadstring) end
    if not G.loadstring then
        wrap("loadstring", function(src, name)
            if type(load) == "function" then
                return load(src, name or "=vt")
            end
            return nil, "loadstring unavailable"
        end)
    end
    wrap("load", load or loadstring)

    wrap("getidentity", getidentity or getthreadidentity or function() return 8 end)
    wrap("setidentity", setidentity or setthreadidentity or function() end)
    wrap("getthreadidentity", getthreadidentity or getidentity)
    wrap("setthreadidentity", setthreadidentity or setidentity)
    wrap("getthreadcontext", getthreadidentity)
    wrap("setthreadcontext", setthreadidentity)

    wrap("isrbxactive", isrbxactive or isgameactive or function() return true end)
    wrap("isgameactive", isgameactive or isrbxactive)
    wrap("iswindowactive", isrbxactive)

    wrap("setclipboard", setclipboard or toclipboard or function() end)
    wrap("toclipboard", toclipboard or setclipboard)
    wrap("getclipboard", getclipboard or function() return "" end)

    wrap("queue_on_teleport", queue_on_teleport or queueonteleport or function() end)
    wrap("queueonteleport", queueonteleport or queue_on_teleport)

    wrap("request", request or http_request or httpget and function(o)
        o = o or {}
        local body = httpget(o.Url or o.url or "")
        return { Body = body, StatusCode = 200, Success = true, Headers = {} }
    end)
    wrap("http_request", http_request or request)
    wrap("httpget", httpget)
    wrap("httpgetasync", httpgetasync or httpget)

    -- Drawing already registered in C if offsets allow.
    wrap("cleardrawcache", cleardrawcache or function()
        if Drawing and Drawing.clear then Drawing.clear() end
    end)

    wrap("cloneref", cloneref or function(x) return x end)
    wrap("compareinstances", compareinstances or function(a, b) return a == b end)
    wrap("getrawmetatable", getrawmetatable or getmetatable)
    wrap("setrawmetatable", setrawmetatable or setmetatable)
    wrap("setreadonly", setreadonly or function(t, _) return t end)
    wrap("makewritable", makewritable or function(t)
        if setreadonly then setreadonly(t, false) end
        return t
    end)
    wrap("isreadonly", isreadonly or function() return false end)
    wrap("islclosure", islclosure or function(f) return type(f) == "function" end)
    wrap("iscclosure", iscclosure or function() return false end)
    wrap("isexecutorclosure", isexecutorclosure or checkcaller or function() return true end)
    wrap("checkclosure", isexecutorclosure)
    wrap("clonefunction", clonefunction or function(f) return f end)
    wrap("newcclosure", newcclosure or function(f) return f end)
    wrap("replaceclosure", replaceclosure or hookfunction)

    wrap("getnamecallmethod", getnamecallmethod or function() return "" end)
    wrap("setnamecallmethod", setnamecallmethod or function() end)

    wrap("getinstances", getinstances or function()
        local out = {}
        pcall(function()
            for _, v in ipairs(game:GetDescendants()) do
                out[#out+1] = v
            end
        end)
        return out
    end)
    wrap("getloadedmodules", getloadedmodules or function()
        local out = {}
        pcall(function()
            for _, v in ipairs(game:GetDescendants()) do
                if v:IsA("ModuleScript") then out[#out+1] = v end
            end
        end)
        return out
    end)
    wrap("getrunningscripts", getrunningscripts or function()
        local out = {}
        pcall(function()
            for _, v in ipairs(game:GetDescendants()) do
                if v:IsA("LocalScript") or v:IsA("Script") then out[#out+1] = v end
            end
        end)
        return out
    end)
    wrap("getscripts", getscripts or getrunningscripts)
    wrap("isnewcclosure", isnewcclosure or function() return false end)

    wrap("fireclickdetector", fireclickdetector or function(d)
        pcall(function()
            if d and d.MouseClick then
                -- soft: try to invoke .MouseClick if it is a Bindable
            end
        end)
    end)
    wrap("fireproximityprompt", fireproximityprompt or function(p)
        pcall(function()
            if p and p.InputHoldBegin then p:InputHoldBegin() end
            if p and p.InputHoldEnd then p:InputHoldEnd() end
        end)
    end)
    wrap("firetouchinterest", firetouchinterest or function() end)
    wrap("gettouchingparts", gettouchingparts or function() return {} end)

    wrap("gethui", gethui or function()
        local h = G.__vt_hui
        if h then return h end
        local okGui, gui = pcall(function()
            local f = Instance.new("Folder")
            f.Name = "CoreUI"
            local core = game:GetService("CoreGui")
            f.Parent = core
            return f
        end)
        if okGui and gui then
            G.__vt_hui = gui
            return gui
        end
        local okPlr, gui2 = pcall(function()
            local lp = game:GetService("Players").LocalPlayer
            local pg = lp:FindFirstChildOfClass("PlayerGui") or lp:WaitForChild("PlayerGui", 2)
            local sg = Instance.new("ScreenGui")
            sg.Name = "CoreUI"
            sg.ResetOnSpawn = false
            sg.Parent = pg
            return sg
        end)
        if okPlr and gui2 then
            G.__vt_hui = gui2
            return gui2
        end
        return nil
    end)

    wrap("protectgui", protectgui or function(g) return g end)
    wrap("protect_gui", protect_gui or protectgui)
    wrap("getcustomasset", getcustomasset or function(p) return p end)
    wrap("getsynasset", getsynasset or getcustomasset)
    wrap("setfpscap", setfpscap or function() end)
    wrap("getfpscap", getfpscap or function() return 60 end)
    wrap("saveinstance", saveinstance or function() end)
    wrap("lz4compress", lz4compress or function(s) return s end)
    wrap("lz4decompress", lz4decompress or function(s) return s end)
    wrap("isscriptable", isscriptable or function() return true end)
    wrap("setscriptable", setscriptable or function() return true end)
    wrap("getscriptfromthread", getscriptfromthread or function() return nil end)
    wrap("getthreadidentity", getthreadidentity or getidentity)
    wrap("isnetworkowner", isnetworkowner or function() return false end)
    wrap("setsimulationradius", setsimulationradius or function() end)
    wrap("getsimulationradius", getsimulationradius or function() return 0 end)
    wrap("isrenderobj", isrenderobj or function() return false end)
    wrap("getrenderproperty", getrenderproperty or function() return nil end)
    wrap("setrenderproperty", setrenderproperty or function() end)
    wrap("cleardrawcache", cleardrawcache or function() if Drawing and Drawing.clear then Drawing.clear() end end)
    wrap("getactors", getactors or function() return {} end)
    wrap("getconnections", getconnections or function() return {} end)
    wrap("replicatesignal", replicatesignal or firesignal)
    wrap("cansignalreplicate", cansignalreplicate or function() return false end)
    wrap("getfflag", getfflag or function() return nil end)
    wrap("setfflag", setfflag or function() end)
    wrap("isnewcclosure", isnewcclosure or function() return false end)
    wrap("dumpstring", dumpstring or function(s) return tostring(s) end)
    wrap("decompile", decompile or function() return "-- decompile unavailable" end)

    if not G.hookfunction then
        wrap("hookfunction", function(old, new)
            if type(new) ~= "function" then return old end
            local function try_replace(t)
                if type(t) ~= "table" then return end
                for k, v in pairs(t) do
                    if v == old then
                        rawset(t, k, new)
                    end
                end
            end
            pcall(try_replace, G)
            pcall(try_replace, _G)
            return old
        end)
    end
    wrap("hookfunc", hookfunc or hookfunction)
    wrap("replaceclosure", replaceclosure or hookfunction)
    wrap("detourfunction", detourfunction or hookfunction)

    if not G.hookmetamethod then
        wrap("hookmetamethod", function(obj, method, hook)
            local mt = getrawmetatable(obj)
            if type(mt) ~= "table" then return nil end
            pcall(function() setreadonly(mt, false) end)
            local old = rawget(mt, method)
            rawset(mt, method, newcclosure and newcclosure(hook) or hook)
            pcall(function() setreadonly(mt, true) end)
            return old
        end)
    end

    -- Roblox already has debug.traceback / debug.info. Do not fake Synapse debug.*.
    G.debug = G.debug or debug or {}
    if debug then
        G.debug.traceback = G.debug.traceback or debug.traceback
        G.debug.info = G.debug.info or debug.info
        G.debug.profilebegin = G.debug.profilebegin or debug.profilebegin
        G.debug.profileend = G.debug.profileend or debug.profileend
    end

    -- crypt
    G.crypt = G.crypt or {}
    G.crypt.base64encode = G.crypt.base64encode or base64_encode or function(s) return s end
    G.crypt.base64decode = G.crypt.base64decode or base64_decode or function(s) return s end
    G.crypt.base64_encode = G.crypt.base64encode
    G.crypt.base64_decode = G.crypt.base64decode
    G.crypt.encrypt = G.crypt.encrypt or function(s) return s end
    G.crypt.decrypt = G.crypt.decrypt or function(s) return s end
    G.crypt.generatebytes = G.crypt.generatebytes or function(n)
        n = n or 16
        local t = {}
        for i = 1, n do t[i] = string.char(math.random(0, 255)) end
        return table.concat(t)
    end
    G.crypt.generatekey = G.crypt.generatekey or function() return G.crypt.generatebytes(32) end
    G.crypt.hash = G.crypt.hash or function(s) return tostring(s) end

    -- cache
    G.cache = G.cache or {}
    G.cache.invalidate = G.cache.invalidate or function() end
    G.cache.iscached = G.cache.iscached or function() return true end
    G.cache.replace = G.cache.replace or function() end

    -- WebSocket stub (scripts check the table, real sockets need a C backend)
    G.WebSocket = G.WebSocket or {}
    G.WebSocket.connect = G.WebSocket.connect or websocketconnect or function(url)
        return {
            Url = url,
            Send = function() end,
            Close = function() end,
            OnMessage = { Connect = function() return { Disconnect = function() end } end },
            OnClose = { Connect = function() return { Disconnect = function() end } end },
        }
    end
    wrap("websocketconnect", websocketconnect or function(u) return G.WebSocket.connect(u) end)

    -- rconsole
    wrap("rconsoleprint", rconsoleprint or print)
    wrap("rconsoleinfo", rconsoleinfo or print)
    wrap("rconsolewarn", rconsolewarn or warn)
    wrap("rconsoleerr", rconsoleerr or warn)
    wrap("rconsolecreate", rconsolecreate or function() end)
    wrap("rconsoledestroy", rconsoledestroy or function() end)
    wrap("rconsoleclear", rconsoleclear or function() end)
    wrap("rconsolename", rconsolename or function() end)
    wrap("rconsoleinput", rconsoleinput or function() return "" end)

    wrap("messagebox", messagebox or function(text, title)
        print("[messagebox]", title, text)
        return 1
    end)

    wrap("getmouseposition", getmouseposition or getmousepos or function()
        return 0, 0
    end)
    wrap("getmousepos", getmousepos or getmouseposition)

    do
        local oldprint = print
        print = function(...)
            local n = select("#", ...)
            local t = {}
            for i = 1, n do t[i] = tostring(select(i, ...)) end
            local s = table.concat(t, "\t")
            pcall(function()
                if rconsoleprint then rconsoleprint(s) end
            end)
            if oldprint then return oldprint(...) end
        end
        wrap("print", print)
    end

    wrap("mouse1down", mouse1down or mouse1press)
    wrap("mouse1up", mouse1up or mouse1release)
    wrap("mouse2down", mouse2down or mouse2press)
    wrap("mouse2up", mouse2up or mouse2release)
    wrap("iswindowactive", iswindowactive or isrbxactive)
    wrap("getobjects", getobjects or function(asset)
        local ok, inst = pcall(function()
            return game:GetObjects(asset)
        end)
        if ok then return inst end
        return {}
    end)

    -- game:HttpGet / HttpGetAsync — hubs load remote scripts this way.
    -- Host also rewrites game:HttpGet(...) -> httpget(...) on Execute.
    wrap("HttpGet", HttpGet or httpget)
    wrap("HttpGetAsync", HttpGetAsync or httpget)
    pcall(function()
        if typeof and typeof(game) == "Instance" and httpget then
            rawset(game, "HttpGet", httpget)
            rawset(game, "HttpGetAsync", httpget)
        end
    end)
    pcall(function()
        if G.__vt_http_namecall then return end
        local old = hookmetamethod and hookmetamethod(game, "__namecall", function(self, ...)
            local method = getnamecallmethod and getnamecallmethod() or ""
            if method == "HttpGet" or method == "HttpGetAsync" then
                local url = ...
                if httpget then return httpget(tostring(url)) end
            end
            return old(self, ...)
        end)
        G.__vt_http_namecall = true
    end)
    pcall(function()
        if typeof and typeof(game) == "Instance" then
            -- userdata methods usually reject this; ignore failure
            rawset = rawset
        end
    end)

    -- VoidTrace only. No fake third-party executor identity.
    -- syn.request is kept as an HTTP *API name* scripts already call, not a brand flag.
    G.syn = G.syn or {}
    G.syn.request = G.syn.request or request
    G.syn.crypt = G.syn.crypt or G.crypt
    G.syn.queue_on_teleport = G.syn.queue_on_teleport or queue_on_teleport
    G.syn.protect_gui = G.syn.protect_gui or protectgui
    G.syn.secure_call = G.syn.secure_call or function(fn, ...) return fn(...) end
    G.http = G.http or { request = request }
    G.fluxus = G.fluxus or { request = request }
    G.shared = G.shared or shared or G
    if shared == nil then shared = G.shared end
    G.identifyexecutor = identifyexecutor
    G.VOIDTRACE_LOADED = true
    G.VoidTrace = { version = "0.3.0", loaded = true, name = "VoidTrace" }

    if Drawing then
        G.Drawing = Drawing
        Drawing.Fonts = Drawing.Fonts or { UI = 0, System = 1, Plex = 2, Monospace = 3 }
    end
end)

if not ok then
    warn("[VoidTrace] init layer: " .. tostring(err))
end
)LUA";

} // namespace vt
