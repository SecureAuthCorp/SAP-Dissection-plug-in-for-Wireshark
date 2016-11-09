Vagrant.configure(2) do |config|

  config.vm.box = "ubuntu/xenial64"

  # Permit X11 forwarding so running the graphical Wireshark works
  config.ssh.forward_x11 = true

  # Define a Vagrant VM to compile as a standalone plugin
  config.vm.define "standalone" do |standalone|
    standalone.vm.provision "shell",
      path: "tools/ubuntu-provision-standalone.sh",
      privileged: false,
      env: {"WIRESHARK_BRANCH" => "master-2.0",
            "PLUGIN_DIR" => "/vagrant/"}

    standalone.vm.provision "shell",
      path: "tools/ubuntu-build-standalone.sh",
      privileged: false,
      env: {"WIRESHARK_BRANCH" => "master-2.0",
            "PLUGIN_DIR" => "/vagrant/"}
  end

  # Define a Vagrant VM to compile from source
  config.vm.define "source" do |source|
    source.vm.provision "shell",
      path: "tools/ubuntu-provision-source.sh",
      privileged: false,
      env: {"WIRESHARK_BRANCH" => "master-2.0",
            "PLUGIN_DIR" => "/vagrant/"}

    source.vm.provision "shell",
      path: "tools/ubuntu-build-source.sh",
      privileged: false,
      env: {"WIRESHARK_BRANCH" => "master-2.0",
            "PLUGIN_DIR" => "/vagrant/"}
  end

end
