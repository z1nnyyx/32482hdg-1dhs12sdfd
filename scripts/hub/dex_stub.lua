-- Placeholder hub script. Drop real scripts here and double-click them in the UI.
print("[VoidTrace] hub script loaded")

-- Example Drawing object (paints on the external overlay after Inject).
local line = Drawing.new("Line")
line.Visible = true
line.Thickness = 2
line.From = { X = 40, Y = 40 }
line.To   = { X = 240, Y = 40 }
line.Color = { R = 160, G = 80, B = 255 }
