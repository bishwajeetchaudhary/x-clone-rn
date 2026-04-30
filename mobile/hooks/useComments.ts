import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Alert } from "react-native";
import { useApiClient, commentApi } from "../utils/api";

export const useComments = () => {
  const [commentText, setCommentText] = useState("");
  const api = useApiClient();

  const queryClient = useQueryClient();

  const createCommentMutation = useMutation({
    mutationFn: async ({postId, content}:{postId:string, content:string}) => {
      const response = await commentApi.createComment(api, postId, content);
      return response.data;
    },
    onSuccess: () => {
      setCommentText("");
      queryClient.invalidateQueries({queryKey: ["posts"]})
    },
    onError: () => {
      Alert.alert("Error", "Failed to create comment. Please try again.");
    }
  })

  const createComment = (postId:string) => {
    if (!commentText.trim()) {
      Alert.alert("Empty Comment", "Please enter a comment before posting.");
      return;
    }
    createCommentMutation.mutate({postId, content: commentText.trim()});
  }

  return {
    commentText,
    setCommentText,
    createComment,
    isCreatingCommnet: createCommentMutation.isPending,
  }
}