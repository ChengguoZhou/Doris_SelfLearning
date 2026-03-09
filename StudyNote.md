**2024'CCS论文《Practical Non-interactive Encrypted Conjunctive Search with Leakage Suppression》——Doris方案代码学习笔记**

# 一、项目文件架构总览

## 1、核心协议层

> Doris
> ├── OXT.py              # OXT 协议 [1] - 基础方案
> ├── HXT.py              # HXT 协议 [2] - 使用 SHVE 工具隐藏结果模式
> ├── ConjFilter_alter.py # ConjFilter 改进版 [3] - 支持单关键词搜索
> ├── ConjFilter_ori.py   # ConjFilter 原始版本
> ├── Doris_XF.py         # Doris 协议 [4] - 使用 SSPE_XF 工具的最新方案

## 2、密码学工具层（Utils）

> Utils/
>
> ├── cryptoUtils.py      # 基础密码学原语：PRF, AES 加解密，Hash
> ├── TSet.py             # TSet 数据结构（带标签的查找表）
> ├── BF.py               # Bloom Filter（布隆过滤器）
> ├── SHVE.py             # 对称隐藏向量加密（HXT 使用）
> ├── SSPE_XF.py          # 基于 XorFilter 的集合加密（Doris 使用）
> ├── XorFilter.py        # Xor Filter 数据结构
> └── fileUtils.py        # 文件读取工具

## 3、数据层（data/）

> data/
> ├── enron_*            # Enron 邮件数据集（索引和倒排索引）
> ├── enwiki_*           # 英文维基百科数据集
> └── wid.csv, idw.csv   # 词到文档 ID 的映射

## 4、实验评估层（根目录）

> ├── setup_exp.py       # Setup 阶段性能测试
> ├── tools_exp.py       # 密码学工具对比实验
> ├── two_keywords_exp.py # 双关键词查询实验
> └── multi_keywords_exp.py # 多关键词查询实验

# 🔐 二、四大协议详解与伪代码对照

## **协议1：OXT(CRYPTO 2013)**

> 核心结构:
> EDB: 包含 TSet + BF (Bloom Filter)
> Setup: 构建 TSet 和 XSet（用 BF 存储）
> Search: 使用 STag 检索 TSet，用 XToken 验证 XSet

## 协议 2: HXT (CCS 2018)

> 改进点: 使用 SHVE（Symmetric Hidden Vector Encryption） 替代明文 BF，隐藏访问模式