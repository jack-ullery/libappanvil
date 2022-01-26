#!/usr/bin/env ruby

require 'mkmf'

# hack 1: Before extconf.rb gets called, Makefile gets backed up, and
#         restored afterwards (see Makefile.am)

if ENV['PREFIX']
  prefix = CONFIG['prefix']
  %w[ prefix sitedir datadir infodir mandir oldincludedir ].each do |key|
    CONFIG[key] = CONFIG[key].sub(/#{prefix}/, ENV['PREFIX'])
  end
end

dir_config('LibAppArmor')
if find_library('apparmor', 'parse_record', '../../src/.libs') and
  have_header('aalogparse.h')
  create_makefile('LibAppArmor')

  # hack 2: strip all rpath references
  open('Makefile.ruby', 'w') do |out|
    IO.foreach('Makefile') do |line|
      out.puts line.gsub(/-Wl,-R'[^']*'/, '')
    end
  end
else
  puts 'apparmor lib not found'
end

