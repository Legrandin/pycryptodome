import pstats
p = pstats.Stats('read.profile')
p.sort_stats('cumulative').print_stats()
