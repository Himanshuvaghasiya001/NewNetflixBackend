# from django.shortcuts import render

# # Create your views here.
# from rest_framework.decorators import api_view
# from .models import Product
# from .serializer import productSerializer
# from rest_framework.response import Response
# from rest_framework import status


# # Create your views here.

# @api_view(['GET','POST'])
# def get_Product(request):
    
#     if request.method == "GET":
#         products = Product.objects.all()
#         serializer = productSerializer(products,many=True)
#         return Response(serializer.data)

#     elif request.method == "POST":
#         serializer = productSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data,status=status.HTTP_201_CREATED)
#         return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

# @api_view(['GET','PUT','DELETE'])
# def detail_Product(request,pk):
#     try:
#         product = Product.objects.get(pk=pk)
#     except Product.DoesNotExist:
#         return Response(status=status.HTTP_404_NOT_FOUND)
    
#     if request.method == "GET":
#         serializer = productSerializer(product)
#         return Response(serializer.data)
    
#     if request.method == "PUT":
#         serializer = productSerializer(product,data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

#     elif request.method == "DELETE":
#         product.delete()
#         return Response(status=status.HTTP_204_NO_CONTENT)

