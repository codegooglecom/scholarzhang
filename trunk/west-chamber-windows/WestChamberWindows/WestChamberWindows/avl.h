#pragma once
typedef struct ncp_avl_node {
	unsigned short value;
	struct ncp_avl_node *avl_left;
	struct ncp_avl_node *avl_right;
	struct ncp_avl_node *next;
	unsigned char avl_height;
}avl_node;
void avl_insert(struct ncp_avl_node * new_node, struct ncp_avl_node ** ptree);
avl_node* avl_create(unsigned short val);
avl_node* avl_search(avl_node* tree,unsigned short val);
void avl_delete(avl_node* node);