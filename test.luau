local function fibonacciNumber(n)
	if n <= 1 then
		return n
	end
	return fibonacciNumber(n - 1)
		+ fibonacciNumber(n - 2)
end

local n = 7
local sum = 0
for i = 0, n do
	sum = sum + fibonacciNumber(i)
end
print("fibonacci sum:", sum)
