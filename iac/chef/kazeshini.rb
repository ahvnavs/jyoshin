# Chef Ohai plugin: /etc/chef/ohai_plugins/kazeshini.rb
# Kazeshini host facts plugin for Chef Infra Client

Ohai.plugin(:Kazeshini) do
  provides 'kazeshini'

  collect_data(:linux) do
    so = shell_out('/usr/local/bin/kazeshini facts --json')
    if so.exitstatus == 0
      begin
        kazeshini Mash.new(FFI_Yajl::Parser.parse(so.stdout))
      rescue
        kazeshini Mash.new
      end
    end
  end
end

