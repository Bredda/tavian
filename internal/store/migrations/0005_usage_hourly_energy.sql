-- Energy and carbon estimates join the hourly sums. Both stay NULL for hours in
-- which no request had an energy profile (or, for carbon, an intensity).
ALTER TABLE usage_hourly
    ADD COLUMN energy_wh double precision,
    ADD COLUMN co2e_g    double precision;
