/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "system_properties/prop_area.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <algorithm>
#include <new>
#include <vector>

#ifdef LARGE_SYSTEM_PROPERTY_NODE
constexpr size_t PA_SIZE = 1024 * 1024;
#else
constexpr size_t PA_SIZE = 128 * 1024;
#endif
constexpr uint32_t PROP_AREA_MAGIC = 0x504f5250;
constexpr uint32_t PROP_AREA_VERSION = 0xfc6ed0ab;

size_t prop_area::pa_size_ = 0;
size_t prop_area::pa_data_size_ = 0;

prop_area* prop_area::map_prop_area_rw(const char* filename, const char* context,
                                       bool* fsetxattr_failed) {
  /* dev is a tmpfs that we can use to carve a shared workspace
   * out of, so let's do that...
   */
  const int fd = open(filename, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_EXCL, 0444);

  if (fd < 0) {
    if (errno == EACCES) {
      /* for consistency with the case where the process has already
       * mapped the page in and segfaults when trying to write to it
       */
      abort();
    }
    return nullptr;
  }

  if (context) {
    if (fsetxattr(fd, XATTR_NAME_SELINUX, context, strlen(context) + 1, 0) != 0) {
      async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                            "fsetxattr failed to set context (%s) for \"%s\": %m", context, filename);
      /*
       * fsetxattr() will fail during system properties tests due to selinux policy.
       * We do not want to create a custom policy for the tester, so we will continue in
       * this function but set a flag that an error has occurred.
       * Init, which is the only daemon that should ever call this function will abort
       * when this error occurs.
       * Otherwise, the tester will ignore it and continue, albeit without any selinux
       * property separation.
       */
      if (fsetxattr_failed) {
        *fsetxattr_failed = true;
      }
    }
  }

  if (ftruncate(fd, PA_SIZE) < 0) {
    close(fd);
    return nullptr;
  }

  pa_size_ = PA_SIZE;
  pa_data_size_ = pa_size_ - sizeof(prop_area);

  void* const memory_area = mmap(nullptr, pa_size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (memory_area == MAP_FAILED) {
    close(fd);
    return nullptr;
  }

  prop_area* pa = new (memory_area) prop_area(PROP_AREA_MAGIC, PROP_AREA_VERSION);

  close(fd);
  return pa;
}

prop_area* prop_area::map_fd_ro(const int fd, bool rw) {
  struct stat fd_stat;
  if (fstat(fd, &fd_stat) < 0) {
    return nullptr;
  }

  if ((fd_stat.st_uid != 0) || (fd_stat.st_gid != 0) ||
      ((fd_stat.st_mode & (S_IWGRP | S_IWOTH)) != 0) ||
      (fd_stat.st_size < static_cast<off_t>(sizeof(prop_area)))) {
    return nullptr;
  }

  pa_size_ = fd_stat.st_size;
  pa_data_size_ = pa_size_ - sizeof(prop_area);

  int prot = rw ? PROT_READ | PROT_WRITE : PROT_READ;
  void* const map_result = mmap(nullptr, pa_size_, prot, MAP_SHARED, fd, 0);
  if (map_result == MAP_FAILED) {
    return nullptr;
  }

  prop_area* pa = reinterpret_cast<prop_area*>(map_result);
  if ((pa->magic() != PROP_AREA_MAGIC) || (pa->version() != PROP_AREA_VERSION)) {
    munmap(pa, pa_size_);
    return nullptr;
  }

  return pa;
}

prop_area* prop_area::map_prop_area(const char* filename, bool *is_rw) {
  bool rw = false;
  int fd = open(filename, O_CLOEXEC | O_NOFOLLOW | O_RDWR);
  if (fd == -1) {
    fd = open(filename, O_CLOEXEC | O_NOFOLLOW | O_RDONLY);
    if (fd == -1) {
      return nullptr;
    }
  } else {
    rw = true;
  }

  prop_area* map_result = map_fd_ro(fd, rw);
  close(fd);

  if (is_rw) *is_rw = rw;
  return map_result;
}

void* prop_area::allocate_obj(const size_t size, uint_least32_t* const off) {
  const size_t aligned = __builtin_align_up(size, sizeof(uint_least32_t));
  if (bytes_used_ + aligned > pa_data_size_) {
    return nullptr;
  }

  *off = bytes_used_;
  bytes_used_ += aligned;
  return data_ + *off;
}

prop_trie_node* prop_area::new_prop_trie_node(const char* name, uint32_t namelen,
                                              uint_least32_t* const off) {
  uint_least32_t new_offset;
  void* const p = allocate_obj(sizeof(prop_trie_node) + namelen + 1, &new_offset);
  if (p == nullptr) return nullptr;

  prop_trie_node* node = new (p) prop_trie_node(name, namelen);
  *off = new_offset;
  return node;
}

prop_info* prop_area::new_prop_info(const char* name, uint32_t namelen, const char* value,
                                    uint32_t valuelen, uint_least32_t* const off) {
  uint_least32_t new_offset;
  void* const p = allocate_obj(sizeof(prop_info) + namelen + 1, &new_offset);
  if (p == nullptr) return nullptr;

  prop_info* info;
  if (valuelen >= PROP_VALUE_MAX) {
    uint32_t long_value_offset = 0;
    char* long_location = reinterpret_cast<char*>(allocate_obj(valuelen + 1, &long_value_offset));
    if (!long_location) return nullptr;

    memcpy(long_location, value, valuelen);
    long_location[valuelen] = '\0';

    // Both new_offset and long_value_offset are offsets based off of data_, however prop_info
    // does not know what data_ is, so we change this offset to be an offset from the prop_info
    // pointer that contains it.
    long_value_offset -= new_offset;

    info = new (p) prop_info(name, namelen, long_value_offset);
  } else {
    info = new (p) prop_info(name, namelen, value, valuelen);
  }
  *off = new_offset;
  return info;
}

void* prop_area::to_prop_obj(uint_least32_t off) {
  if (off > pa_data_size_) return nullptr;

  return (data_ + off);
}

inline prop_trie_node* prop_area::to_prop_trie_node(atomic_uint_least32_t* off_p) {
  uint_least32_t off = atomic_load_explicit(off_p, memory_order_consume);
  return reinterpret_cast<prop_trie_node*>(to_prop_obj(off));
}

inline prop_info* prop_area::to_prop_info(atomic_uint_least32_t* off_p) {
  uint_least32_t off = atomic_load_explicit(off_p, memory_order_consume);
  return reinterpret_cast<prop_info*>(to_prop_obj(off));
}

inline prop_trie_node* prop_area::root_node() {
  return reinterpret_cast<prop_trie_node*>(to_prop_obj(0));
}

static int cmp_prop_name(const char* one, uint32_t one_len, const char* two, uint32_t two_len) {
  if (one_len < two_len)
    return -1;
  else if (one_len > two_len)
    return 1;
  else
    return strncmp(one, two, one_len);
}

prop_trie_node* prop_area::find_prop_trie_node(prop_trie_node* const trie, const char* name,
                                               uint32_t namelen, bool alloc_if_needed) {
  prop_trie_node* current = trie;
  while (true) {
    if (!current) {
      return nullptr;
    }

    const int ret = cmp_prop_name(name, namelen, current->name, current->namelen);
    if (ret == 0) {
      return current;
    }

    if (ret < 0) {
      uint_least32_t left_offset = atomic_load_explicit(&current->left, memory_order_relaxed);
      if (left_offset != 0) {
        current = to_prop_trie_node(&current->left);
      } else {
        if (!alloc_if_needed) {
          return nullptr;
        }

        uint_least32_t new_offset;
        prop_trie_node* new_node = new_prop_trie_node(name, namelen, &new_offset);
        if (new_node) {
          atomic_store_explicit(&current->left, new_offset, memory_order_release);
        }
        return new_node;
      }
    } else {
      uint_least32_t right_offset = atomic_load_explicit(&current->right, memory_order_relaxed);
      if (right_offset != 0) {
        current = to_prop_trie_node(&current->right);
      } else {
        if (!alloc_if_needed) {
          return nullptr;
        }

        uint_least32_t new_offset;
        prop_trie_node* new_node = new_prop_trie_node(name, namelen, &new_offset);
        if (new_node) {
          atomic_store_explicit(&current->right, new_offset, memory_order_release);
        }
        return new_node;
      }
    }
  }
}

prop_trie_node* prop_area::traverse_trie(prop_trie_node *const trie, const char *name,
                                         bool alloc_if_needed) {
  if (!trie) return nullptr;

  const char* remaining_name = name;
  prop_trie_node* current = trie;
  while (true) {
    const char* sep = strchr(remaining_name, '.');
    const bool want_subtree = (sep != nullptr);
    const uint32_t substr_size = (want_subtree) ? sep - remaining_name : strlen(remaining_name);

    if (!substr_size) {
      return nullptr;
    }

    prop_trie_node* root = nullptr;
    uint_least32_t children_offset = atomic_load_explicit(&current->children, memory_order_relaxed);
    if (children_offset != 0) {
      root = to_prop_trie_node(&current->children);
    } else if (alloc_if_needed) {
      uint_least32_t new_offset;
      root = new_prop_trie_node(remaining_name, substr_size, &new_offset);
      if (root) {
        atomic_store_explicit(&current->children, new_offset, memory_order_release);
      }
    }

    if (!root) {
      return nullptr;
    }

    current = find_prop_trie_node(root, remaining_name, substr_size, alloc_if_needed);
    if (!current) {
      return nullptr;
    }

    if (!want_subtree) break;

    remaining_name = sep + 1;
  }

  return current;
}

const prop_info* prop_area::find_property(prop_trie_node* const trie, const char* name,
                                          uint32_t namelen, const char* value, uint32_t valuelen,
                                          bool alloc_if_needed) {
  prop_trie_node* current = traverse_trie(trie, name, alloc_if_needed);
  if (!current) return nullptr;

  uint_least32_t prop_offset = atomic_load_explicit(&current->prop, memory_order_relaxed);
  if (prop_offset != 0) {
    return to_prop_info(&current->prop);
  } else if (alloc_if_needed) {
    uint_least32_t new_offset;
    prop_info* new_info = new_prop_info(name, namelen, value, valuelen, &new_offset);
    if (new_info) {
      atomic_store_explicit(&current->prop, new_offset, memory_order_release);
    }

    return new_info;
  } else {
    return nullptr;
  }
}

bool prop_area::foreach_property(prop_trie_node* const trie,
                                 void (*propfn)(const prop_info* pi, void* cookie), void* cookie) {
  if (!trie) return false;

  uint_least32_t left_offset = atomic_load_explicit(&trie->left, memory_order_relaxed);
  if (left_offset != 0) {
    if (!foreach_property(to_prop_trie_node(&trie->left), propfn, cookie)) return false;
  }
  uint_least32_t prop_offset = atomic_load_explicit(&trie->prop, memory_order_relaxed);
  if (prop_offset != 0) {
    prop_info* info = to_prop_info(&trie->prop);
    if (!info) return false;
    propfn(info, cookie);
  }
  uint_least32_t children_offset = atomic_load_explicit(&trie->children, memory_order_relaxed);
  if (children_offset != 0) {
    if (!foreach_property(to_prop_trie_node(&trie->children), propfn, cookie)) return false;
  }
  uint_least32_t right_offset = atomic_load_explicit(&trie->right, memory_order_relaxed);
  if (right_offset != 0) {
    if (!foreach_property(to_prop_trie_node(&trie->right), propfn, cookie)) return false;
  }

  return true;
}

const prop_info* prop_area::find(const char* name) {
  return find_property(root_node(), name, strlen(name), nullptr, 0, false);
}

bool prop_area::add(const char* name, unsigned int namelen, const char* value,
                    unsigned int valuelen) {
  return find_property(root_node(), name, namelen, value, valuelen, true);
}

bool prop_area::foreach(void (*propfn)(const prop_info* pi, void* cookie), void* cookie) {
  return foreach_property(root_node(), propfn, cookie);
}

#define get_offset(ptr)        atomic_load_explicit(ptr, memory_order_relaxed)
#define set_offset(ptr, val)   atomic_store_explicit(ptr, val, memory_order_release)

namespace {

struct LiveObject {
  uint_least32_t old_offset;
  uint32_t size;
  uint32_t aligned_size;
  uint_least32_t new_offset;
};

struct LongValueRef {
  uint_least32_t prop_old_offset;
  uint_least32_t long_old_offset;
};

inline uint_least32_t ptr_to_offset(const char* base, const void* ptr) {
  return static_cast<uint_least32_t>(reinterpret_cast<const char*>(ptr) - base);
}

inline prop_trie_node* offset_to_node(char* base, uint_least32_t off) {
  return reinterpret_cast<prop_trie_node*>(base + off);
}

inline prop_info* offset_to_info(char* base, uint_least32_t off) {
  return reinterpret_cast<prop_info*>(base + off);
}

void collect_live_objects(char* base, prop_trie_node* node, bool skip_node,
                          std::vector<LiveObject>& objects,
                          std::vector<uint_least32_t>& node_offsets,
                          std::vector<uint_least32_t>& prop_offsets,
                          std::vector<LongValueRef>& long_refs) {
  if (!node) return;

  if (!skip_node) {
    uint_least32_t node_off = ptr_to_offset(base, node);
    uint32_t node_size = sizeof(prop_trie_node) + node->namelen + 1;
    objects.push_back({node_off, node_size,
                       static_cast<uint32_t>(
                           __builtin_align_up(node_size, sizeof(uint_least32_t))),
                       0u});
    node_offsets.push_back(node_off);
  }

  uint_least32_t prop_off = get_offset(&node->prop);
  if (prop_off != 0) {
    prop_info* info = offset_to_info(base, prop_off);
    uint32_t name_len = strlen(info->name);
    uint32_t info_size = sizeof(prop_info) + name_len + 1;
    objects.push_back({prop_off, info_size,
                       static_cast<uint32_t>(
                           __builtin_align_up(info_size, sizeof(uint_least32_t))),
                       0u});
    prop_offsets.push_back(prop_off);

    if (info->is_long()) {
      const char* long_val = info->long_value();
      uint32_t long_len = strlen(long_val);
      uint_least32_t long_off = ptr_to_offset(base, long_val);
      uint32_t long_size = long_len + 1;
      objects.push_back({long_off, long_size,
                         static_cast<uint32_t>(
                             __builtin_align_up(long_size, sizeof(uint_least32_t))),
                         0u});
      long_refs.push_back({prop_off, long_off});
    }
  }

  uint_least32_t left_offset = get_offset(&node->left);
  if (left_offset != 0) {
    collect_live_objects(base, offset_to_node(base, left_offset), false, objects,
                         node_offsets, prop_offsets, long_refs);
  }
  uint_least32_t children_offset = get_offset(&node->children);
  if (children_offset != 0) {
    collect_live_objects(base, offset_to_node(base, children_offset), false, objects,
                         node_offsets, prop_offsets, long_refs);
  }
  uint_least32_t right_offset = get_offset(&node->right);
  if (right_offset != 0) {
    collect_live_objects(base, offset_to_node(base, right_offset), false, objects,
                         node_offsets, prop_offsets, long_refs);
  }
}

}  // namespace

// After removing a property, it is possible that redundant nodes will appear in the trie.
// DFS through the data structure, remove leaf nodes that do not hold properties, remove
// them from the trie, then backtrack recursively and remove redundant parent nodes.
// When this method returns true, detach the node from the parent.
bool prop_area::prune_trie(prop_trie_node *const node) {
  bool is_leaf = true;
  if (get_offset(&node->children) != 0) {
    if (prune_trie(to_prop_trie_node(&node->children))) {
      set_offset(&node->children, 0u);
    } else {
      is_leaf = false;
    }
  }
  if (get_offset(&node->left) != 0) {
    if (prune_trie(to_prop_trie_node(&node->left))) {
      set_offset(&node->left, 0u);
    } else {
      is_leaf = false;
    }
  }
  if (get_offset(&node->right) != 0) {
    if (prune_trie(to_prop_trie_node(&node->right))) {
      set_offset(&node->right, 0u);
    } else {
      is_leaf = false;
    }
  }

  if (is_leaf && get_offset(&node->prop) == 0) {
    // Wipe the node
    memset(node->name, 0, node->namelen);
    memset(node, 0, sizeof(*node));
    // Then return true to detach the node from parent
    return true;
  }
  return false;
}

bool prop_area::remove(const char *name, bool prune) {
  prop_trie_node *node = traverse_trie(root_node(), name, false);
  if (!node) return false;

  uint_least32_t prop_offset = get_offset(&node->prop);
  if (prop_offset == 0) return false;

  prop_info *prop = to_prop_info(&node->prop);

  // Detach the property from trie ASAP
  set_offset(&node->prop, 0u);

  // Then wipe out the property from memory
  if (prop->is_long()) {
    char *value = const_cast<char*>(prop->long_value());
    memset(value, 0, strlen(value));
  }
  memset(prop->name, 0, strlen(prop->name));
  memset(prop, 0, sizeof(*prop));

  if (prune) {
    prune_trie(root_node());
  }

  return true;
}

bool prop_area::compact() {
  const uint32_t data_start = sizeof(prop_trie_node) +
                              __builtin_align_up(PROP_VALUE_MAX, sizeof(uint_least32_t));
  const uint32_t old_bytes_used = bytes_used_;
  if (old_bytes_used < data_start) {
    return false;
  }

  std::vector<LiveObject> objects;
  std::vector<uint_least32_t> node_offsets;
  std::vector<uint_least32_t> prop_offsets;
  std::vector<LongValueRef> long_refs;

  collect_live_objects(data_, root_node(), true, objects, node_offsets, prop_offsets, long_refs);

  if (objects.empty()) {
    if (old_bytes_used != data_start) {
      memset(data_ + data_start, 0, old_bytes_used - data_start);
      bytes_used_ = data_start;
    }
    return true;
  }

  std::sort(objects.begin(), objects.end(),
            [](const LiveObject& a, const LiveObject& b) { return a.old_offset < b.old_offset; });
  std::sort(long_refs.begin(), long_refs.end(),
            [](const LongValueRef& a, const LongValueRef& b) {
              return a.prop_old_offset < b.prop_old_offset;
            });

  uint32_t next = data_start;
  for (auto& obj : objects) {
    obj.new_offset = next;
    next += obj.aligned_size;
  }

  for (const auto& obj : objects) {
    if (obj.new_offset != obj.old_offset) {
      memmove(data_ + obj.new_offset, data_ + obj.old_offset, obj.aligned_size);
    }
  }

  if (next < old_bytes_used) {
    memset(data_ + next, 0, old_bytes_used - next);
  }
  bytes_used_ = next;

  auto remap_offset = [&objects](uint_least32_t old_off) -> uint_least32_t {
    if (old_off == 0) return 0;
    auto it = std::lower_bound(
        objects.begin(), objects.end(), old_off,
        [](const LiveObject& obj, uint_least32_t off) { return obj.old_offset < off; });
    if (it == objects.end() || it->old_offset != old_off) {
      return old_off;
    }
    return it->new_offset;
  };

  auto update_node = [&remap_offset](prop_trie_node* node) {
    uint_least32_t left = get_offset(&node->left);
    if (left != 0) set_offset(&node->left, remap_offset(left));
    uint_least32_t right = get_offset(&node->right);
    if (right != 0) set_offset(&node->right, remap_offset(right));
    uint_least32_t children = get_offset(&node->children);
    if (children != 0) set_offset(&node->children, remap_offset(children));
    uint_least32_t prop = get_offset(&node->prop);
    if (prop != 0) set_offset(&node->prop, remap_offset(prop));
  };

  update_node(root_node());
  for (uint_least32_t old_off : node_offsets) {
    uint_least32_t new_off = remap_offset(old_off);
    update_node(offset_to_node(data_, new_off));
  }

  for (uint_least32_t prop_old_off : prop_offsets) {
    uint_least32_t prop_new_off = remap_offset(prop_old_off);
    prop_info* info = offset_to_info(data_, prop_new_off);
    if (!info->is_long()) continue;

    auto it = std::lower_bound(
        long_refs.begin(), long_refs.end(), prop_old_off,
        [](const LongValueRef& ref, uint_least32_t off) { return ref.prop_old_offset < off; });
    if (it == long_refs.end() || it->prop_old_offset != prop_old_off) {
      continue;
    }

    uint_least32_t long_new_off = remap_offset(it->long_old_offset);
    info->long_property.offset = long_new_off - prop_new_off;
  }

  return true;
}
