-- Belgium Voice ESP — Highlight + nametag
-- Does NOT use Drawing. Inject, wait READY, then F5.
-- Stop: _G.VT_ESP = false

local Players = game:GetService("Players")
local lp = Players.LocalPlayer

if _G.VT_ESP_OFF then pcall(_G.VT_ESP_OFF) end
_G.VT_ESP = true

local tags = {}

local function paint(plr)
    if plr == lp then return end
    local ch = plr.Character
    if not ch then return end
    local head = ch:FindFirstChild("Head")
    local hum = ch:FindFirstChildOfClass("Humanoid")
    if not head then return end

    local hl = ch:FindFirstChild("_vt_hl")
    if not hl then
        hl = Instance.new("Highlight")
        hl.Name = "_vt_hl"
        hl.FillColor = Color3.fromRGB(70, 140, 255)
        hl.OutlineColor = Color3.fromRGB(180, 220, 255)
        hl.FillTransparency = 0.55
        hl.OutlineTransparency = 0
        hl.DepthMode = Enum.HighlightDepthMode.AlwaysOnTop
        hl.Adornee = ch
        hl.Parent = ch
    end

    local bg = head:FindFirstChild("_vt_tag")
    if not bg then
        bg = Instance.new("BillboardGui")
        bg.Name = "_vt_tag"
        bg.Size = UDim2.new(0, 200, 0, 36)
        bg.StudsOffset = Vector3.new(0, 2.6, 0)
        bg.AlwaysOnTop = true
        bg.Parent = head
        local t = Instance.new("TextLabel")
        t.Name = "T"
        t.BackgroundTransparency = 1
        t.Size = UDim2.new(1, 0, 1, 0)
        t.Font = Enum.Font.GothamBold
        t.TextSize = 16
        t.TextColor3 = Color3.new(1, 1, 1)
        t.TextStrokeTransparency = 0.4
        t.Parent = bg
    end
    local dist = 0
    if lp.Character and lp.Character:FindFirstChild("HumanoidRootPart") and ch:FindFirstChild("HumanoidRootPart") then
        dist = (lp.Character.HumanoidRootPart.Position - ch.HumanoidRootPart.Position).Magnitude
    end
    bg.T.Text = string.format("%s  %dm", plr.DisplayName, math.floor(dist))
    tags[plr] = true
end

local function clear()
    for _, p in ipairs(Players:GetPlayers()) do
        local ch = p.Character
        if ch then
            local h = ch:FindFirstChild("_vt_hl")
            if h then h:Destroy() end
            local head = ch:FindFirstChild("Head")
            if head then
                local b = head:FindFirstChild("_vt_tag")
                if b then b:Destroy() end
            end
        end
    end
    tags = {}
end

_G.VT_ESP_OFF = function()
    _G.VT_ESP = false
    clear()
end

Players.PlayerRemoving:Connect(function(p) tags[p] = nil end)

task.spawn(function()
    while _G.VT_ESP do
        for _, p in ipairs(Players:GetPlayers()) do
            pcall(paint, p)
        end
        task.wait(0.35)
    end
    clear()
end)

print("[VT] Belgium Voice Highlight ESP on")
print("stop:  _G.VT_ESP = false")
