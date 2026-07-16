class Point
    public x: number
    public y: number

    function new(x, y)
        return Point { x = x, y = y }
    end
end

local p = Point.new(3, 4)
print(`Check out my cool point: {p}`)
