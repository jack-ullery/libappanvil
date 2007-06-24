require 'mkmf'
require 'ftools'

$CFLAGS   += " " + (ENV['CFLAGS'] || "") + (ENV['CXXFLAGS'] || "")
$LDFLAGS = "../../src/.libs/libaalogparse.so"

def usage
	puts <<EOF
Usage: ruby extconf.rb command
	build				Build the extension
	clean				Clean the source directory
	install				Install the extention
	test				Test the extension
	wrap				Generate SWIG wrappers
EOF
	exit
end

cmd = ARGV.shift or usage()
cmd = cmd.downcase

usage() unless ['build', 'clean', 'install', 'test', 'wrap'].member? cmd
usage() if ARGV.shift

class Commands
	def initialize(&block)
		@block = block
	end
	
	def execute
		@block.call
	end
end

Build = Commands.new {
	# I don't think we can tell mkmf to generate a makefile with a different name
	if File.exists?("Makefile")
		File.rename("Makefile", "Makefile.old")
	end
	create_makefile('AppArmorLogRecordParser')
	File.rename("Makefile", "Makefile.ruby")
	if File.exists?("Makefile.old")
		File.rename("Makefile.old", "Makefile")
	end
	system("make -f Makefile.ruby")
}
Install = Commands.new {
    Build.execute
    if defined? Prefix
        # strip old prefix and add the new one
        oldPrefix = Config::CONFIG["prefix"]
        if defined? Debian
          archDir = Config::CONFIG["archdir"]
          libDir = Config::CONFIG["rubylibdir"]
        else
          archDir = Config::CONFIG["sitearchdir"]
          libDir = Config::CONFIG["sitelibdir"]
        end
        archDir    = Prefix + archDir.gsub(/^#{oldPrefix}/,"")
        libDir     = Prefix + libDir.gsub(/^#{oldPrefix}/,"")
    else
        archDir    = Config::CONFIG["sitearchdir"]
        libDir     = Config::CONFIG["sitelibdir"]
    end
    [archDir,libDir].each { |path| File.makedirs path }
     	 binary = 'AppArmorLogRecordParser.so'
    File.install "./"+binary, archDir+"/"+binary, 0555, true
    File.install "./AppArmorLogRecordParser.so", libDir+"/AppArmorLogRecordParser.so", 0555, true
}

availableCommands = {
	"build"	=> Build,
	"install" => Install
}

availableCommands[cmd].execute
