#pragma once

// Seeded into %LOCALAPPDATA%\VoidTrace on first run so the friend
// never needs extra files next to the exe.

inline constexpr char kDefaultOffsetsJson[] = R"JSON({
  "roblox_version": "version-ce0bcd0fbd484804",
  "auto_attach": false,
  "auto_inject": true,
  "task_scheduler": "0x88B64C8",
  "job_name": "0x18",
  "job_start": "0xC8",
  "job_end": "0xD0",
  "script_context": "0x0",
  "extra_space": "0x78",
  "lua_state": "0x110",
  "identity": "0x30",
  "luau_load": "0x0",
  "lua_pcall": "0x0",
  "lua_getfield": "0x0",
  "lua_setfield": "0x0",
  "lua_tolstring": "0x0",
  "lua_pushvalue": "0x0",
  "lua_pushnil": "0x0",
  "lua_pushnumber": "0x0",
  "lua_pushstring": "0x0",
  "lua_pushboolean": "0x0",
  "lua_pushcclosure": "0x0",
  "lua_newthread": "0x0",
  "lua_settop": "0x0",
  "lua_gettop": "0x0",
  "lua_type": "0x0",
  "lua_createtable": "0x0",
  "lua_settable": "0x0",
  "lua_gettable": "0x0",
  "lua_newuserdata": "0x0",
  "lua_setmetatable": "0x0",
  "lua_getmetatable": "0x0",
  "lua_toboolean": "0x0",
  "lua_tonumber": "0x0",
  "lua_pushlstring": "0x0",
  "fake_datamodel": "0x8B79B58",
  "visual_engine": "0x8136228",
  "fake_dm_off": "0x1D8",
  "child_off": "0x78",
  "name_off": "0x70",
  "class_desc": "0x18",
  "character": "0x298",
  "local_player": "0x130",
  "primitive": "0x188",
  "position": "0xEC",
  "view_matrix": "0x180",
  "humanoid_hp": "0x190",
  "humanoid_maxhp": "0x1A8",
  "root_part": "0x258",
  "pat_task_scheduler": "",
  "pat_luau_load": "",
  "pat_lua_pcall": ""
})JSON";

inline constexpr char kWelcomeLua[] = R"LUA(-- Runs automatically after Inject once READY.
print("[VoidTrace]", identifyexecutor())
)LUA";

inline constexpr char kEspLua[] = R"LUA(-- Auto Highlight ESP. Stop: _G.VT_ESP = false
local Players = game:GetService("Players")
local lp = Players.LocalPlayer
_G.VT_ESP = true
local function paint(p)
    if p == lp then return end
    local ch = p.Character
    if not ch then return end
    local head = ch:FindFirstChild("Head")
    if not head then return end
    if not ch:FindFirstChild("_vt_hl") then
        local h = Instance.new("Highlight")
        h.Name = "_vt_hl"
        h.FillColor = Color3.fromRGB(70, 140, 255)
        h.OutlineColor = Color3.fromRGB(200, 230, 255)
        h.FillTransparency = 0.55
        h.DepthMode = Enum.HighlightDepthMode.AlwaysOnTop
        h.Adornee = ch
        h.Parent = ch
    end
    if not head:FindFirstChild("_vt_tag") then
        local bg = Instance.new("BillboardGui")
        bg.Name = "_vt_tag"
        bg.Size = UDim2.new(0, 180, 0, 28)
        bg.StudsOffset = Vector3.new(0, 2.5, 0)
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
    local d = 0
    local a, b = lp.Character and lp.Character:FindFirstChild("HumanoidRootPart"), ch:FindFirstChild("HumanoidRootPart")
    if a and b then d = (a.Position - b.Position).Magnitude end
    head._vt_tag.T.Text = string.format("%s  %dm", p.DisplayName, math.floor(d))
end
task.spawn(function()
    while _G.VT_ESP do
        for _, p in ipairs(Players:GetPlayers()) do pcall(paint, p) end
        task.wait(0.4)
    end
end)
print("[VT] Highlight ESP on")
)LUA";

inline constexpr char kHubExampleLua[] = R"LUA(-- Double-click this in the script list to load it into the editor.
print("[VoidTrace] example hub script")
print("identifyexecutor =", identifyexecutor())
)LUA";
