#!/bin/sh
# 只停用本项目新增的旁路服务，保留统计数据库以便之后恢复。
set -eu
/etc/init.d/zashboard-stats disable
/etc/init.d/zashboard-stats stop
printf '%s\n' '统计定制版已停用，数据库已保留。' '请打开原版入口：http://192.168.50.2:9090/ui/' '本脚本不修改 Nikki 配置、原版面板和分流选择。'
