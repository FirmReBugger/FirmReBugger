if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)."
  exit 1
fi

# Setup inotify limits
echo 524288 > /proc/sys/fs/inotify/max_user_watches
echo 512 > /proc/sys/fs/inotify/max_user_instances
# cat /proc/sys/fs/inotify/max_user_watches
# cat /proc/sys/fs/inotify/max_user_instances

# Setup core dumps
echo core > /proc/sys/kernel/core_pattern