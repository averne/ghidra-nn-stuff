/*
 * Copyright (c) 2018-2020 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once
// #include <vapours/util/util_parent_of_member.hpp>

namespace nn::util {

    /* Forward declare implementation class for Node. */
    namespace impl {

        class IntrusiveListImpl;

    }

    class IntrusiveListNode {
        NON_COPYABLE(IntrusiveListNode);
        private:
            friend class impl::IntrusiveListImpl;

            IntrusiveListNode *prev;
            IntrusiveListNode *next;
        public:
            constexpr IntrusiveListNode() : prev(this), next(this) { /* ... */ }

            constexpr bool IsLinked() const {
                return this->next != this;
            }
        private:
            void LinkPrev(IntrusiveListNode *node) {
                /* We can't link an already linked node. */
                AMS_ASSERT(!node->IsLinked());
                this->SplicePrev(node, node);
            }

            void SplicePrev(IntrusiveListNode *first, IntrusiveListNode *last) {
                /* Splice a range into the list. */
                auto last_prev = last->prev;
                first->prev = this->prev;
                this->prev->next = first;
                last_prev->next = this;
                this->prev = last_prev;
            }

            void LinkNext(IntrusiveListNode *node) {
                /* We can't link an already linked node. */
                AMS_ASSERT(!node->IsLinked());
                return this->SpliceNext(node, node);
            }

            void SpliceNext(IntrusiveListNode *first, IntrusiveListNode *last) {
                /* Splice a range into the list. */
                auto last_prev = last->prev;
                first->prev = this;
                last_prev->next = next;
                this->next->prev = last_prev;
                this->next = first;
            }

            void Unlink() {
                this->Unlink(this->next);
            }

            void Unlink(IntrusiveListNode *last) {
                /* Unlink a node from a next node. */
                auto last_prev = last->prev;
                this->prev->next = last;
                last->prev = this->prev;
                last_prev->next = this;
                this->prev = last_prev;
            }

            IntrusiveListNode *GetPrev() {
                return this->prev;
            }

            const IntrusiveListNode *GetPrev() const {
                return this->prev;
            }

            IntrusiveListNode *GetNext() {
                return this->next;
            }

            const IntrusiveListNode *GetNext() const {
                return this->next;
            }
    };
    static_assert(std::is_literal_type<IntrusiveListNode>::value);

}