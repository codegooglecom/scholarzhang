#pragma once
BOOLEAN InitializeIpTable(LPCWSTR binary_file);
BOOLEAN IsInIpTable(unsigned int ip_val);
void DeInitializeIpTable();