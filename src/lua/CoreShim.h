#pragma once

// Luau prepended onto corescript bytecode. Roblox env only — no C UNC.
// Drawing/mouse/files so Energy Assault, Bloxstrike, and similar hubs run.

namespace vt {

inline constexpr char kCoreShim[] = R"LUA(
print("[VoidTrace] exec", identifyexecutor and identifyexecutor() or "VoidTrace")
local G = _G
G.getgenv = G.getgenv or function() return G end
G.getrenv = G.getrenv or function() return G end
G.identifyexecutor = G.identifyexecutor or function() return "VoidTrace","0.3.0" end
G.getexecutorname = G.getexecutorname or function() return "VoidTrace" end
G.checkcaller = G.checkcaller or function() return true end
G.cloneref = G.cloneref or function(x) return x end
G.newcclosure = G.newcclosure or function(f) return f end
G.iscclosure = G.iscclosure or function() return false end
G.islclosure = G.islclosure or function(f) return type(f) == "function" end
G.setclipboard = G.setclipboard or function() end
G.toclipboard = G.toclipboard or G.setclipboard
G.getclipboard = G.getclipboard or function() return "" end
G.writefile = G.writefile or function() end
G.readfile = G.readfile or function() return "" end
G.appendfile = G.appendfile or function() end
G.isfile = G.isfile or function() return false end
G.isfolder = G.isfolder or function() return false end
G.makefolder = G.makefolder or function() end
G.listfiles = G.listfiles or function() return {} end
G.delfile = G.delfile or function() end
G.delfolder = G.delfolder or function() end
G.loadfile = G.loadfile or function() return function() end end
G.gethui = G.gethui or function()
    local ok, cg = pcall(function() return game:GetService("CoreGui") end)
    if ok and cg then return cg end
    return game:GetService("Players").LocalPlayer:WaitForChild("PlayerGui")
end
G.isrbxactive = G.isrbxactive or function() return true end
G.isgameactive = G.isrbxactive
G.hookfunction = G.hookfunction or function(a) return a end
G.replaceclosure = G.hookfunction
G.getthreadidentity = G.getthreadidentity or function() return 8 end
G.setthreadidentity = G.setthreadidentity or function() end
G.getidentity = G.getthreadidentity
G.setidentity = G.setthreadidentity
G.queue_on_teleport = G.queue_on_teleport or function() end
G.queueonteleport = G.queue_on_teleport
pcall(function()
    local vim = game:GetService("VirtualInputManager")
    local uis = game:GetService("UserInputService")
    G.mousemoverel = G.mousemoverel or function(dx, dy)
        local p = uis:GetMouseLocation()
        vim:SendMouseMoveEvent(p.X + (dx or 0), p.Y + (dy or 0), workspace)
    end
    G.mousemoveabs = G.mousemoveabs or function(x, y)
        vim:SendMouseMoveEvent(x, y, workspace)
    end
    G.mouse1click = G.mouse1click or function()
        vim:SendMouseButtonEvent(0, 0, 0, true, workspace, 1)
        vim:SendMouseButtonEvent(0, 0, 0, false, workspace, 1)
    end
    G.mouse1press = G.mouse1press or function() vim:SendMouseButtonEvent(0, 0, 0, true, workspace, 1) end
    G.mouse1release = G.mouse1release or function() vim:SendMouseButtonEvent(0, 0, 0, false, workspace, 1) end
    G.keypress = G.keypress or function(k) vim:SendKeyEvent(true, k, false, workspace) end
    G.keyrelease = G.keyrelease or function(k) vim:SendKeyEvent(false, k, false, workspace) end
end)
if not G.Drawing then
    local gui = Instance.new("ScreenGui")
    gui.Name = "VTDraw"
    gui.IgnoreGuiInset = true
    gui.ResetOnSpawn = false
    gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    pcall(function() gui.Parent = G.gethui() end)
    if not gui.Parent then
        pcall(function() gui.Parent = game:GetService("Players").LocalPlayer:WaitForChild("PlayerGui") end)
    end
    local function col(c)
        if typeof(c) == "Color3" then return c end
        return Color3.new(1, 1, 1)
    end
    local function mk(ty)
        local o = { Visible = true, Color = Color3.new(1,1,1), Transparency = 0, Thickness = 1, ZIndex = 50, Filled = false }
        local n = Instance.new(ty == "Text" and "TextLabel" or "Frame")
        n.BorderSizePixel = 0
        n.BackgroundColor3 = Color3.new(1,1,1)
        n.Parent = gui
        local stroke
        if ty == "Circle" then
            Instance.new("UICorner", n).CornerRadius = UDim.new(1, 0)
            stroke = Instance.new("UIStroke", n)
            o.Radius = 20
            o.Position = Vector2.new(0, 0)
        elseif ty == "Line" then
            n.AnchorPoint = Vector2.new(0.5, 0.5)
            o.From = Vector2.new(0, 0)
            o.To = Vector2.new(0, 0)
        elseif ty == "Text" then
            n.BackgroundTransparency = 1
            n.Font = Enum.Font.Gotham
            n.TextSize = 13
            n.TextStrokeTransparency = 0
            n.TextXAlignment = Enum.TextXAlignment.Left
            o.Text = ""
            o.Size = 13
            o.Center = false
            o.Outline = true
            o.OutlineColor = Color3.new(0, 0, 0)
            o.Position = Vector2.new(0, 0)
        else
            o.Size = Vector2.new(10, 10)
            o.Position = Vector2.new(0, 0)
            stroke = Instance.new("UIStroke", n)
        end
        local function upd()
            n.Visible = o.Visible and true or false
            n.ZIndex = o.ZIndex or 50
            local t = o.Transparency or 0
            if ty == "Circle" then
                local d = (o.Radius or 0) * 2
                local p = o.Position or Vector2.new(0, 0)
                n.Size = UDim2.fromOffset(d, d)
                n.Position = UDim2.fromOffset(p.X - d / 2, p.Y - d / 2)
                n.BackgroundColor3 = col(o.Color)
                n.BackgroundTransparency = o.Filled and t or 1
                if stroke then stroke.Color = col(o.Color) stroke.Thickness = o.Thickness or 1 stroke.Transparency = t end
            elseif ty == "Line" then
                local a, b = o.From or Vector2.new(), o.To or Vector2.new()
                local dx, dy = b.X - a.X, b.Y - a.Y
                local len = math.sqrt(dx * dx + dy * dy)
                n.Size = UDim2.fromOffset(len, o.Thickness or 1)
                n.Position = UDim2.fromOffset((a.X + b.X) / 2, (a.Y + b.Y) / 2)
                n.Rotation = math.deg(math.atan2(dy, dx))
                n.BackgroundColor3 = col(o.Color)
                n.BackgroundTransparency = t
            elseif ty == "Text" then
                n.Text = tostring(o.Text or "")
                n.TextColor3 = col(o.Color)
                n.TextSize = o.Size or 13
                n.TextTransparency = t
                n.TextStrokeColor3 = col(o.OutlineColor)
                n.TextStrokeTransparency = o.Outline and 0 or 1
                n.TextXAlignment = o.Center and Enum.TextXAlignment.Center or Enum.TextXAlignment.Left
                local p = o.Position or Vector2.new()
                n.Position = UDim2.fromOffset(p.X, p.Y)
                n.Size = UDim2.fromOffset(400, (o.Size or 13) + 4)
            else
                local p = o.Position or Vector2.new()
                local s = o.Size or Vector2.new(10, 10)
                n.Position = UDim2.fromOffset(p.X, p.Y)
                n.Size = UDim2.fromOffset(s.X, s.Y)
                n.BackgroundColor3 = col(o.Color)
                n.BackgroundTransparency = o.Filled and t or 1
                if stroke then stroke.Color = col(o.Color) stroke.Thickness = o.Thickness or 1 stroke.Transparency = t stroke.Enabled = not o.Filled end
            end
        end
        upd()
        return setmetatable(o, {
            __index = function(_, k)
                if k == "Remove" or k == "Destroy" then return function() n:Destroy() end end
                return rawget(o, k)
            end,
            __newindex = function(_, k, v) rawset(o, k, v) upd() end
        })
    end
    G.Drawing = {
        Fonts = { UI = 0, System = 1, Plex = 2, Monospace = 3 },
        new = function(ty)
            ty = tostring(ty or "Square")
            if ty == "Quad" or ty == "Triangle" then ty = "Square" end
            return mk(ty)
        end,
        clear = function() for _, c in ipairs(gui:GetChildren()) do c:Destroy() end end
    }
    G.cleardrawcache = G.Drawing.clear
end
)LUA";

inline constexpr char kCoreShimTiny[] = R"LUA(
local G=_G
G.identifyexecutor=function()return"VoidTrace","0.3"end
G.getexecutorname=G.identifyexecutor
)LUA";

inline constexpr char kCoreShimMin[] = R"LUA(
local G=_G
G.identifyexecutor=function()return"VoidTrace","0.3"end
G.getexecutorname=G.identifyexecutor
G.getgenv=function()return G end
G.gethui=function()return game:GetService("CoreGui")end
G.checkcaller=function()return true end
G.isrbxactive=function()return true end
G.getthreadidentity=function()return 8 end
G.setthreadidentity=function()end
G.hookfunction=function(a)return a end
G.newcclosure=function(f)return f end
G.cloneref=function(x)return x end
)LUA";

} // namespace vt
