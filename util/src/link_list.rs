// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::marker::PhantomData;
use std::ptr::NonNull;

pub struct Node<T> {
    prev: Option<NonNull<Node<T>>>,
    next: Option<NonNull<Node<T>>>,
    pub value: T,
}

#[derive(Default)]
pub struct List<T> {
    head: Option<NonNull<Node<T>>>,
    tail: Option<NonNull<Node<T>>>,
    len: usize,
    marker: PhantomData<Box<Node<T>>>,
}

// SAFETY: Implementing Send and Sync is safe for List<T>
// because only locked access(r/w) is permitted
unsafe impl<T> Sync for List<T> {}
// SAFETY: Same as above
unsafe impl<T> Send for List<T> {}

impl<T> Drop for List<T> {
    fn drop(&mut self) {
        while self.pop_head().is_some() {}
    }
}

impl<T> Node<T> {
    pub fn new(value: T) -> Self {
        Node {
            prev: None,
            next: None,
            value,
        }
    }
}

impl<T> List<T> {
    pub fn new() -> Self {
        List {
            head: None,
            tail: None,
            len: 0,
            marker: PhantomData,
        }
    }

    #[inline]
    pub fn add_tail(&mut self, mut node: Box<Node<T>>) {
        node.prev = self.tail;
        node.next = None;

        let node = NonNull::new(Box::into_raw(node));
        if let Some(mut t) = self.tail {
            // SAFETY: t is guaranteed not to be null.
            unsafe { t.as_mut() }.next = node;
        } else {
            self.head = node;
            self.tail = node;
        }

        self.tail = node;
        self.len += 1;
    }

    #[inline]
    pub fn add_head(&mut self, mut node: Box<Node<T>>) {
        node.prev = None;
        node.next = self.head;
        let node = NonNull::new(Box::into_raw(node));
        if let Some(mut h) = self.head {
            // SAFETY: h is guaranteed not to be null.
            unsafe { h.as_mut() }.prev = node;
        } else {
            self.head = node;
            self.tail = node;
        }

        self.head = node;
        self.len += 1;
    }

    #[inline]
    pub fn unlink(&mut self, node: &Node<T>) {
        match node.prev {
            // SAFETY: p is guaranteed not to be null.
            Some(mut p) => unsafe { p.as_mut() }.next = node.next,
            None => self.head = node.next,
        }

        match node.next {
            // SAFETY: n is guaranteed not to be null.
            Some(mut n) => unsafe { n.as_mut() }.prev = node.prev,
            None => self.tail = node.prev,
        }
        self.len -= 1;
    }

    #[inline]
    pub fn pop_tail(&mut self) -> Option<Box<Node<T>>> {
        self.tail.map(|node| {
            // SAFETY: node is guaranteed not to be null.
            let node = unsafe { Box::from_raw(node.as_ptr()) };
            self.tail = node.prev;

            match self.tail {
                None => self.head = None,
                // SAFETY: t is guaranteed not to be null.
                Some(mut t) => unsafe { t.as_mut() }.next = None,
            }

            self.len -= 1;
            node
        })
    }

    #[inline]
    pub fn pop_head(&mut self) -> Option<Box<Node<T>>> {
        self.head.map(|node| {
            // SAFETY: node is guaranteed not to be null.
            let node = unsafe { Box::from_raw(node.as_ptr()) };
            self.head = node.next;

            match self.head {
                None => self.tail = None,
                // SAFETY: h is guaranteed not to be null.
                Some(mut h) => unsafe { h.as_mut() }.prev = None,
            }

            self.len -= 1;
            node
        })
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline(always)]
    pub fn iter(&'_ self) -> impl Iterator<Item = &'_ T> {
        Iter::new(self)
    }

    #[inline(always)]
    pub fn iter_mut(&'_ mut self) -> impl Iterator<Item = &'_ mut T> {
        IterMut::new(self)
    }
}

struct Iter<'a, T> {
    curr: Option<NonNull<Node<T>>>,
    list: PhantomData<&'a List<T>>,
}

impl<'a, T> Iter<'a, T> {
    fn new(list: &'a List<T>) -> Self {
        Self {
            curr: list.head,
            list: PhantomData,
        }
    }
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        self.curr.map(|node| {
            // SAFETY: node is guaranteed not to be null.
            let node = unsafe { node.as_ref() };
            self.curr = node.next;
            &node.value
        })
    }
}

struct IterMut<'a, T> {
    curr: Option<NonNull<Node<T>>>,
    list: PhantomData<&'a mut List<T>>,
}

impl<'a, T> IterMut<'a, T> {
    fn new(list: &'a mut List<T>) -> Self {
        Self {
            curr: list.head,
            list: PhantomData,
        }
    }
}

impl<'a, T> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        self.curr.map(|mut node| {
            // SAFETY: node is guaranteed not to be null.
            let node = unsafe { node.as_mut() };
            self.curr = node.next;
            &mut node.value
        })
    }
}
